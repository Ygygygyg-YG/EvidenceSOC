"""Shared figure style and table contract, fixed before formal results."""
import math

import matplotlib

matplotlib.use("Agg")
from matplotlib import pyplot as plt

GROUPS = ("B0", "B1", "B2", "B3", "A1", "A2", "A3", "A4")
COLORS = ("#466f8e", "#56947f", "#ab7a48", "#564c83", "#a05b66", "#7a8771", "#5c8e93", "#8e795c")
CSV_FIELDS = ("dataset", "group", "metric", "value", "denominator", "status", "direction", "unit", "note")


def number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def get(value, path, default=None):
    for key in path.split("."):
        if not isinstance(value, dict):
            return default
        value = value.get(key)
    return default if value is None else value


def record(dataset, group, metric, value, denominator=None, *, direction="higher", unit="ratio", note=""):
    return {"dataset": dataset, "group": group, "metric": metric,
            "value": value if number(value) else None, "denominator": denominator,
            "status": "computed" if number(value) else "not_available",
            "direction": direction, "unit": unit, "note": note}


def canvas(title, panels, columns=2):
    rows = math.ceil(panels / columns)
    figure, axes = plt.subplots(rows, columns, figsize=(11, max(4.8, 3.5 * rows)), squeeze=False)
    figure.suptitle(title, fontsize=16, fontweight="bold", y=.985)
    flat = list(axes.flat)
    for axis in flat[panels:]:
        axis.set_visible(False)
    return figure, flat[:panels]


def bars(axis, labels, values, title, *, unit="比例", bounds=None, zero=False, notes=None):
    axis.set_title(title, loc="left", fontsize=11, pad=12)
    for index, (label, value) in enumerate(zip(labels, values, strict=True)):
        if number(value):
            axis.bar(index, value, width=.62, color=COLORS[index % len(COLORS)],
                     edgecolor="white", hatch=("", "/", "\\", "..", "xx", "--", "++", "oo")[index % 8])
            axis.annotate(f"{value:.3g}", (index, value), xytext=(0, 5 if value >= 0 else -12),
                          textcoords="offset points", ha="center", fontsize=8)
        else:
            axis.text(index, .04, "N/A", ha="center", va="bottom", transform=axis.get_xaxis_transform(), fontsize=8)
        if notes and notes[index]:
            axis.text(index, -.22, notes[index], ha="center", va="top", transform=axis.get_xaxis_transform(), fontsize=7)
    axis.set_xticks(range(len(labels)), labels, fontsize=9)
    axis.set_xlim(-.6, len(labels) - .4)
    axis.set_ylabel(unit, fontsize=9)
    axis.spines[["top", "right"]].set_visible(False)
    axis.grid(axis="y", alpha=.18)
    axis.set_axisbelow(True)
    if bounds:
        axis.set_ylim(*bounds)
    if zero:
        axis.axhline(0, color="#444444", linewidth=.8)
    if not any(number(value) for value in values):
        axis.text(.5, .55, "无可计算数据 / N/A", transform=axis.transAxes, ha="center", color="#666666")


def finish(figure, footer):
    figure.text(.025, .018, footer, ha="left", va="bottom", fontsize=8, color="#555555", wrap=True)
    figure.tight_layout(rect=(.015, .08, .99, .95), h_pad=3, w_pad=2)
