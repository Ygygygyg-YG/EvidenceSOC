"""Evidence-anchored instance matching and frozen partial-order scoring."""
from .classification import applicable, diagnosis, prediction, ratio


def _matching(gold, predicted):
    candidates = {g["instance_id"]: [p["instance_id"] for p in predicted
        if p.get("phase") == g.get("phase") and set(g.get("evidence_ids", [])) & set(p.get("evidence_ids", []))]
        for g in gold}
    matched = {}

    def augment(gold_id, visited):
        for predicted_id in candidates[gold_id]:
            if predicted_id in visited:
                continue
            visited.add(predicted_id)
            if predicted_id not in matched or augment(matched[predicted_id], visited):
                matched[predicted_id] = gold_id
                return True
        return False

    for gold_id in candidates:
        augment(gold_id, set())
    return {gold_id: predicted_id for predicted_id, gold_id in matched.items()}


def _closure(instances, edges):
    ids = {item["instance_id"] for item in instances}
    if len(ids) != len(instances):
        raise ValueError("Stage instance IDs must be unique")
    relations = set()
    for left, right in edges:
        if left not in ids or right not in ids or left == right:
            raise ValueError("Frozen stage relation refers to invalid instance")
        relations.add((left, right))
    while True:
        expanded = relations | {(a, d) for a, b in relations for c, d in relations if b == c}
        if any(left == right for left, right in expanded):
            raise ValueError("Frozen partial order must be acyclic")
        if expanded == relations:
            return relations
        relations = expanded


def score_attack_chain(rows):
    gold_n = predicted_n = matched_n = comparable = correct = selected_n = 0
    for row in rows:
        if not applicable(row, "phases"):
            continue
        selected_n += 1
        gold = row.get("gold", {}).get("stage_instances", [])
        predicted = (diagnosis(row) or {}).get("stage_instances", []) if prediction(row) == "attack" else []
        if len({p["instance_id"] for p in predicted}) != len(predicted):
            raise ValueError("Predicted stage instance IDs must be unique")
        matched = _matching(gold, predicted)
        gold_n += len(gold)
        predicted_n += len(predicted)
        matched_n += len(matched)
        sequences = {p["instance_id"]: p.get("sequence") for p in predicted}
        for left, right in _closure(gold, row.get("gold", {}).get("precedes", [])):
            comparable += 1
            if left in matched and right in matched:
                a, b = sequences[matched[left]], sequences[matched[right]]
                correct += isinstance(a, int) and isinstance(b, int) and a < b
    return {"applicable_n": selected_n, "gold_instances": gold_n, "predicted_instances": predicted_n,
            "matched_instances": matched_n, "stage_precision": ratio(matched_n, predicted_n) if selected_n else None,
            "stage_recall": ratio(matched_n, gold_n) if selected_n else None,
            "stage_f1": 2 * matched_n / (gold_n + predicted_n) if gold_n + predicted_n else None,
            "comparable_pairs": comparable, "correct_pairs": correct, "order_accuracy": ratio(correct, comparable),
            "status": "computed" if selected_n else "not_applicable",
            "reason": None if selected_n else "No frozen stage-instance and partial-order gold"}
