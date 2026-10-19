"""Pure, denominator-preserving classification metrics; no dataset reads."""
from collections import Counter

SIX_CLASSES = (
    "reconnaissance", "credential_attack", "webshell_upload",
    "remote_command_execution", "privilege_escalation", "data_exfiltration",
)
SUCCESS = {"succeeded", "success", "completed"}


def ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def diagnosis(row):
    result = row.get("result") or {}
    value = row.get("diagnosis", result.get("diagnostic_snapshot"))
    if isinstance(value, dict) and isinstance(value.get("diagnosis"), dict):
        value = value["diagnosis"]
    status = row.get("diagnostic_status", row.get("diagnosis_status", result.get("diagnosis_status", result.get("diagnostic_status", "missing"))))
    return value if status in SUCCESS and isinstance(value, dict) else None


def prediction(row):
    result = row.get("result") or {}
    status = row.get("diagnostic_status", row.get("diagnosis_status", result.get("diagnosis_status", result.get("diagnostic_status", "missing"))))
    value = diagnosis(row)
    if value is not None:
        verdict = value.get("verdict")
        return verdict if verdict in {"attack", "benign", "unknown"} else "missing"
    return "missing" if status in {"missing", "not_dispatched", "not_started"} else "failed"


def applicable(row, metric):
    return row.get("applicability", {}).get(metric) is True


def _counts(tp, fp, fn):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"true_positive": tp, "false_positive": fp, "false_negative": fn,
            "support": tp + fn, "predicted": tp + fp, "precision": precision,
            "recall": recall, "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0}


def score_labels(rows, *, key, mask, labels=None):
    selected = [row for row in rows if applicable(row, mask)]
    if labels is None:
        labels = sorted({label for row in selected for label in row.get("gold", {}).get(key, [])}
                        | {label for row in selected if prediction(row) == "attack"
                           for label in (diagnosis(row) or {}).get(key, [])})
    counts = {label: Counter() for label in labels}
    for row in selected:
        gold = set(row.get("gold", {}).get(key, []))
        predicted = set((diagnosis(row) or {}).get(key, [])) if prediction(row) == "attack" else set()
        for label in labels:
            counts[label]["tp"] += label in gold and label in predicted
            counts[label]["fp"] += label not in gold and label in predicted
            counts[label]["fn"] += label in gold and label not in predicted
    per_class = {label: _counts(c["tp"], c["fp"], c["fn"]) for label, c in counts.items()}
    supported = [value["f1"] for value in per_class.values() if value["support"]]
    totals = Counter()
    for count in counts.values():
        totals.update(count)
    return {"applicable_n": len(selected), "applicable_case_ids": sorted(row.get("case_id", "") for row in selected),
            "status": "computed" if selected else "not_applicable",
            "reason": None if selected else "No frozen applicable gold",
            "macro_f1": (sum(value["f1"] for value in per_class.values()) / len(per_class)
                         if selected and per_class else None),
            "supported_macro_f1": ratio(sum(supported), len(supported)),
            "micro": _counts(totals["tp"], totals["fp"], totals["fn"]) if selected else None,
            "per_class": per_class}


def score_classification(rows):
    selected = [row for row in rows if applicable(row, "attack_binary")]
    confusion = {gold: {pred: 0 for pred in ("attack", "benign", "unknown", "failed", "missing")}
                 for gold in ("attack", "benign")}
    for row in selected:
        truth = row.get("gold", {}).get("is_attack")
        if type(truth) is not bool:
            raise ValueError("Applicable binary gold requires explicit boolean is_attack")
        confusion["attack" if truth else "benign"][prediction(row)] += 1
    positives, negatives = confusion["attack"], confusion["benign"]
    tp, fp = positives["attack"], negatives["attack"]
    positive_n, negative_n = sum(positives.values()), sum(negatives.values())
    n = positive_n + negative_n
    answered = tp + fp + positives["benign"] + negatives["benign"]
    binary = _counts(tp, fp, positive_n - tp) if n else {
        "precision": None, "recall": None, "f1": None}
    binary.update({"applicable_n": n, "applicable_case_ids": sorted(row.get("case_id", "") for row in selected),
                   "positive_n": positive_n, "negative_n": negative_n,
                   "accuracy": ratio(tp + negatives["benign"], n),
                   "fpr": ratio(fp, negative_n), "benign_correct_rate": ratio(negatives["benign"], negative_n),
                   "answer_coverage": ratio(answered, n), "unanswered_rate": ratio(n - answered, n),
                   "benign_unanswered_rate": ratio(sum(negatives[k] for k in ("unknown", "failed", "missing")), negative_n),
                   "conditional_accuracy": ratio(tp + negatives["benign"], answered),
                   "confusion": confusion, "status": "computed" if n else "not_applicable",
                   "reason": None if n else "No frozen applicable binary gold"})
    return {"binary": binary, "six_class": score_labels(rows, key="attack_types", mask="six_class", labels=SIX_CLASSES),
            "techniques": score_labels(rows, key="technique_ids", mask="techniques")}
