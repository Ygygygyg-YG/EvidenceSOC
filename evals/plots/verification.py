"""F8 consumes the frozen verification summary; never calculates scores."""
from .common import bars, canvas, get, record


def build(dataset, verification):
    figure, axes = canvas(f"{dataset.upper()} · F8 效果验证消融（模拟）", 8)
    rows = []
    specs = [("success", "success_rate", "成功条件：判成功比例"),
             ("failure", "false_success_rate", "明确失败：误报成功率 ↓"),
             ("no_change", "false_success_rate", "无变化：误报成功率 ↓"),
             ("failure", "failure_recognition_rate", "明确失败识别率 ↑"),
             ("no_change", "no_change_insufficient_rate", "无变化：证据不足比例")]
    for axis, (condition, metric, title) in zip(axes[:5], specs, strict=True):
        values = []
        for branch in ("enabled", "disabled"):
            summary = get(verification, f"conditions.{condition}", {})
            selected = summary.get("branches", {}).get(branch, {})
            value = selected.get(metric)
            rows.append(record(dataset, branch, f"{condition}.{metric}", value, selected.get("answered_n"),
                               note=f"planned={summary.get('planned_pairs')}; paired_executable={summary.get('executable_pairs')}; simulated only"))
            values.append(value)
        bars(axis, ("B3 启用验证", "A4 禁用验证"), values, title, bounds=(0, 1.14))
    unverified, labels, pair_counts, pair_labels = [], [], [], []
    for condition, label in (("success", "成功"), ("failure", "失败"), ("no_change", "无变化")):
        summary = get(verification, f"conditions.{condition}", {})
        for branch, branch_label in (("enabled", "B3"), ("disabled", "A4")):
            selected = summary.get("branches", {}).get(branch, {})
            value = selected.get("unverified_rate")
            unverified.append(value)
            labels.append(f"{label}\n{branch_label}")
            rows.append(record(dataset, branch, f"{condition}.unverified_rate", value, selected.get("paired_n")))
            rows.append(record(dataset, branch, f"{condition}.answer_coverage", selected.get("answer_coverage"), summary.get("planned_pairs")))
            for status, count in selected.get("all_outcome_counts", {}).items():
                rows.append(record(dataset, branch, f"{condition}.outcome.{status}", count, summary.get("planned_pairs"), unit="count"))
        for metric, metric_label in (("planned_pairs", "计划"), ("executable_pairs", "共同可执行")):
            value = summary.get(metric)
            pair_counts.append(value)
            pair_labels.append(f"{label}\n{metric_label}")
            rows.append(record(dataset, "paired", f"{condition}.{metric}", value, summary.get("planned_pairs"), unit="count"))
    bars(axes[5], labels, unverified, "三条件：未验证比例", bounds=(0, 1.14))
    bars(axes[6], pair_labels, pair_counts, "计划槽位与共同可执行配对", unit="配对数")
    costs = []
    for metric, source in (("additional_cost", "cost"), ("known_additional_cost_subtotal", "known_cost_subtotal")):
        value = verification.get(source)
        costs.append(value)
        rows.append(record(dataset, "all", metric, value, verification.get("planned_branches"),
                           direction="lower", unit="CNY", note=f"missing_cost_branches={verification.get('cost_missing_count')}; known subtotal is not a complete total"))
    bars(axes[7], ("全部额外费用", "已知费用小计"), costs, "独立模拟额外费用（含两分支）", unit="人民币元")
    planned, complete, cases = (verification.get(key, "N/A") for key in ("planned_pairs", "complete_pairs", "cases_complete_all_conditions"))
    return figure, rows, (f"独立克隆配对模拟；计划配对={planned}，共同完成={complete}，三条件完整案例={cases}。"
        "仅比较相同可执行配对；禁用验证为未验证，其误报率为N/A。缺失费用不记零，已知小计不冒充完整费用。不能证明真实阻断。")
