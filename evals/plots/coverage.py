from .common import COLORS, GROUPS, bars, canvas, record


def _status_panel(axis, dataset, groups, key, categories, title):
    rows = []
    bottoms = [0] * len(GROUPS)
    observed = False
    for color, status in zip(COLORS, categories, strict=False):
        heights = []
        for index, group in enumerate(GROUPS):
            coverage = groups.get(group, {}).get("coverage", {})
            mapping = coverage.get(key)
            value = mapping.get(status, 0) if isinstance(mapping, dict) else None
            rows.append(record(dataset, group, f"{key}.{status}", value, coverage.get("planned_n"), unit="count"))
            heights.append(value or 0)
            observed |= value is not None
        axis.bar(range(len(GROUPS)), heights, bottom=bottoms, label=status, color=color, edgecolor="white")
        bottoms = [a + b for a, b in zip(bottoms, heights, strict=True)]
    axis.set_title(title, loc="left", fontsize=11)
    axis.set_xticks(range(len(GROUPS)), GROUPS)
    axis.set_ylabel("计划项数")
    axis.legend(fontsize=7, loc="upper left", bbox_to_anchor=(0, -.18), ncol=3)
    axis.spines[["top", "right"]].set_visible(False)
    if not observed:
        axis.text(.5, .5, "无可计算数据 / N/A", transform=axis.transAxes, ha="center")
    return rows


def build(dataset, groups):
    figure, axes = canvas(f"{dataset.upper()} · F5 状态与覆盖", 4)
    rows = _status_panel(axes[0], dataset, groups, "execution_status",
                         ("completed", "failed", "missing", "started", "interrupted"), "执行状态（独立面板）")
    rows += _status_panel(axes[1], dataset, groups, "diagnostic_status",
                          ("attack", "benign", "unknown", "failed", "missing"), "诊断状态（独立面板）")
    for axis, metric, title in [(axes[2], "answer_coverage", "attack/benign作答覆盖 ↑"),
                                (axes[3], "human_review_coverage", "实际人工复核覆盖")]:
        panel = []
        for group in GROUPS:
            value = groups.get(group, {})
            coverage = value.get("coverage", {})
            n = coverage.get("planned_n")
            score = coverage.get(metric) if metric == "answer_coverage" else value.get("evidence", {}).get(metric)
            rows.append(record(dataset, group, metric, score, n))
            panel.append(score)
        bars(axis, GROUPS, panel, title, bounds=(0, 1.1))
    scope = "Shaw/Wilson分层见评分覆盖表" if dataset == "ait" else "单campaign相关窗口；仅二分类适用；事件适用6563/6600"
    return figure, rows, f"{scope}。执行与诊断分别计数；unknown、失败、missing保留。人工复核仅预登记样本。"
