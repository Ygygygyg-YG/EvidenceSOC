from .common import bars, canvas, get, record


def build(dataset, groups):
    specs = [("binary_f1", "classification.binary.f1", "攻击正类 F1 ↑"),
             ("binary_accuracy", "classification.binary.accuracy", "总体准确率 ↑"),
             ("binary_fpr", "classification.binary.fpr", "正常误报率 ↓")]
    if dataset == "ait":
        specs.insert(0, ("six_class_macro_f1", "classification.six_class.macro_f1", "固定六类 Macro F1 ↑"))
    figure, axes = canvas(f"{dataset.upper()} · F1 基线效果", len(specs))
    rows = []
    for axis, (metric, path, title) in zip(axes, specs, strict=True):
        panel = []
        notes = []
        for group in ("B0", "B1", "B2", "B3"):
            value = groups.get(group, {})
            n = get(value, "classification.six_class.applicable_n" if metric.startswith("six") else "classification.binary.applicable_n")
            unanswered = get(value, "classification.binary.unanswered_rate")
            row = record(dataset, group, metric, get(value, path), n,
                         direction="lower" if metric.endswith("fpr") else "higher")
            rows.append(row)
            panel.append(row["value"])
            notes.append(f"n={n if n is not None else 'N/A'}\n未答={unanswered:.0%}" if unanswered is not None else f"n={n if n is not None else 'N/A'}")
        bars(axis, ("B0", "B1", "B2", "B3"), panel, title, bounds=(0, 1.14), notes=notes)
    return figure, rows, "同一数据集分别评分；未答保留主分母。AIT 固定六类含零支持类；DEDALE 不生成细分类得分。"
