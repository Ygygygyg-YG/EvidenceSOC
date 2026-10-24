from .common import GROUPS, bars, canvas, number, record


def build(dataset, groups):
    specs = [("latency_p50_ms", "控制器耗时 p50", "秒"), ("latency_p95_ms", "控制器耗时 p95", "秒"),
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
            resource = value.get("resources", {})
            planned = value.get("coverage", {}).get("planned_n")
            raw = resource.get(metric)
            denominator = planned
            note = "缺失不计零；已知小计不冒充完整成本。开发/模拟费用另列。"
            display_metric = metric
            if metric in {"latency_p50_ms", "latency_p95_ms"}:
                denominator = resource.get("latency_observed_n")
                missing = resource.get("latency_missing_n")
                note = (f"计划 n={planned}；观察 n={denominator}；缺测 n={missing}。"
                        "控制器 wall time 含隔离启动、清理和已记录尝试；原始毫秒另列。")
                rows.append(record(dataset, group, metric, raw, denominator,
                                   direction="lower", unit="毫秒", note=note))
                display_metric = metric.removesuffix("_ms") + "_s"
                raw = raw / 1000 if number(raw) else None
            row = record(dataset, group, display_metric, raw,
                         denominator, direction="lower", unit=unit, note=note)
            rows.append(row)
            panel.append(row["value"])
        bars(axis, GROUPS, panel, title, unit=unit)
    return figure, rows, ("控制器 wall time 的 p50/p95 以秒展示，CSV 保留原始毫秒；"
                          "包含隔离启动、清理及已记录尝试。失败、重试、获准重跑计正式成本；"
                          "开发/模拟单列。缺失 usage/费用保持 null。")
