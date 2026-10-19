from .common import GROUPS, bars, canvas, record


def build(dataset, groups):
    specs = [("citation_validity", "引用有效率 ↑ · 全量程序检查", "citation_count", "higher"),
             ("p_at_5_lower", "语义 P@5 下界 ↑ · 人工样本", "semantic_denominator_slots", "higher"),
             ("p_at_5_upper", "语义 P@5 上界 ↑ · 人工样本", "semantic_denominator_slots", "higher"),
             ("ucr_lower", "UCR 下界 ↓ · 人工样本", "reviewed_claim_count", "lower"),
             ("ucr_upper", "UCR 上界 ↓ · 人工样本", "reviewed_claim_count", "lower")]
    figure, axes = canvas(f"{dataset.upper()} · F3 证据质量", len(specs))
    rows = []
    for axis, (metric, title, denominator, direction) in zip(axes, specs, strict=True):
        panel, notes = [], []
        for group in GROUPS:
            score = groups.get(group, {}).get("evidence", {})
            n = score.get(denominator)
            row = record(dataset, group, metric, score.get(metric), n, direction=direction,
                         note=f"reviewed_reports={score.get('semantic_reviewed_reports')}; reports={score.get('report_count')}")
            rows.append(row)
            panel.append(row["value"])
            notes.append(f"n={n if n is not None else 'N/A'}")
        bars(axis, GROUPS, panel, title, bounds=(0, 1.14), notes=notes)
    return figure, rows, "人工指标仅限预登记样本；8个底层案例形成64个审核槽位，实际覆盖见CSV。无法判定保留上下界；未审为N/A。"
