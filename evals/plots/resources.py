from .common import GROUPS, bars, canvas, record


def build(dataset, groups):
    specs = [("latency_p50_ms", "耗时 p50", "毫秒"), ("latency_p95_ms", "耗时 p95", "毫秒"),
             ("input_tokens", "输入 Token", "Token"), ("output_tokens", "输出 Token", "Token"),
             ("cost", "正式费用（含失败/获准重跑）", "人民币元"),
             ("development_cost", "开发/校准费用（单列）", "人民币元"),
             ("verification_cost", "独立模拟验证费用（单列）", "人民币元"),
             ("model_logical_calls", "逻辑模型调用", "次"), ("model_retries", "模型重试", "次"),
             ("tool_logical_calls", "逻辑工具调用", "次"), ("tool_physical_attempts", "工具物理尝试", "次")]
    figure, axes = canvas(f"{dataset.upper()} · F4 资源开销", len(specs), columns=3)
    rows = []
    for axis, (metric, title, unit) in zip(axes, specs, strict=True):
        panel = []
        for group in GROUPS:
            value = groups.get(group, {})
            row = record(dataset, group, metric, value.get("resources", {}).get(metric),
                         value.get("coverage", {}).get("planned_n"), direction="lower", unit=unit,
                         note="缺失不计零；已知小计不冒充完整成本。开发/模拟费用另列。")
            rows.append(row)
            panel.append(row["value"])
        bars(axis, GROUPS, panel, title, unit=unit)
    return figure, rows, "p50/p95为线性插值耗时分位数。失败、重试、获准重跑计正式成本；开发/模拟单列。缺失usage/费用保持null。"
