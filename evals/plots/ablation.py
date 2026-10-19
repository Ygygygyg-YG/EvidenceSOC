from .common import bars, canvas, get, number, record


def build(dataset, groups):
    specs = [("binary_f1", "classification.binary.f1", "攻击正类 F1 ↑"),
             ("binary_fpr", "classification.binary.fpr", "正常误报率 ↓")]
    if dataset == "ait":
        specs.insert(0, ("six_class_macro_f1", "classification.six_class.macro_f1", "固定六类 Macro F1 ↑"))
    figure, axes = canvas(f"{dataset.upper()} · F2 消融 − B3", len(specs))
    rows = []
    for axis, (metric, path, title) in zip(axes, specs, strict=True):
        panel = []
        reference = get(groups.get("B3", {}), path)
        for group in ("A1", "A2", "A3", "A4"):
            value = get(groups.get(group, {}), path)
            n = get(groups.get(group, {}), "classification.six_class.applicable_n" if metric.startswith("six") else "classification.binary.applicable_n")
            base_n = get(groups.get("B3", {}), "classification.six_class.applicable_n" if metric.startswith("six") else "classification.binary.applicable_n")
            case_path = "classification.six_class.applicable_case_ids" if metric.startswith("six") else "classification.binary.applicable_case_ids"
            cases = get(groups.get(group, {}), case_path)
            base_cases = get(groups.get("B3", {}), case_path)
            paired = isinstance(cases, list) and isinstance(base_cases, list) and sorted(cases) == sorted(base_cases)
            delta = 100 * (value - reference) if number(value) and number(reference) and n == base_n and paired else None
            row = record(dataset, group, metric, delta, n,
                         direction="lower" if metric.endswith("fpr") else "higher", unit="percentage_points",
                         note="消融−B3；仅同案例同适用分母；A4验证效果见F8")
            rows.append(row)
            panel.append(delta)
        bound = max([abs(value) for value in panel if number(value)] + [1]) * 1.4
        bars(axis, ("A1", "A2", "A3", "A4"), panel, title, unit="百分点", bounds=(-bound, bound), zero=True)
    return figure, rows, "差值统一为消融−B3，0–1指标转百分点；同案例同适用分母。A4处置后验证由F8单列。"
