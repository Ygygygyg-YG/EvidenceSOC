"""Regenerate the fixed 15 figure bundle from immutable scores, never rescore."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
from pathlib import Path

from . import ablation, baseline, coverage, evidence, resources, verification
from .common import CSV_FIELDS, GROUPS, bars, canvas, finish, get, number, record


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def merge_scores(paths):
    """Join separately frozen datasets only when their experiment identity agrees."""
    documents = []
    for path in paths:
        path = Path(path).resolve()
        raw = path.read_bytes()
        documents.append((path, hashlib.sha256(raw).hexdigest(), json.loads(raw.decode("utf-8-sig"))))
    if not documents:
        raise ValueError("At least one frozen score input is required")
    first = documents[0][2]
    identity_keys = ("source_commit", "system_commit", "requested_model", "response_model", "published_version", "model", "thinking")
    required = ("source_commit", "requested_model", "published_version")
    if len(documents) > 1 and any(first.get("metadata", {}).get(key) is None for key in required):
        raise ValueError("Missing model/system identity in frozen score input")
    metadata = dict(first.get("metadata", {}))
    metadata.pop("dataset", None)
    merged = {"schema_version": 1, "run_id": first.get("run_id"), "metadata": metadata,
              "groups": {}, "verification": {}, "source_hashes": {}, "merged_inputs": []}
    for index, (path, digest, document) in enumerate(documents):
        if document.get("run_id") != merged["run_id"] or any(document.get("metadata", {}).get(key) != metadata.get(key) for key in identity_keys):
            raise ValueError("Frozen score model/system/run identity mismatch")
        for dataset, groups in document.get("groups", {}).items():
            if dataset in merged["groups"]:
                raise ValueError("Duplicate dataset in frozen score merge")
            merged["groups"][dataset] = groups
        for dataset, summary in document.get("verification", {}).items():
            if dataset in merged["verification"]:
                raise ValueError("Duplicate verification dataset in frozen score merge")
            merged["verification"][dataset] = summary
        merged["merged_inputs"].append({"path": str(path), "sha256": digest})
        merged["source_hashes"].update({f"input{index}:{key}": value for key, value in document.get("source_hashes", {}).items()})
    metadata["planned_n"] = sum(document.get("metadata", {}).get("planned_n", 0) for _, _, document in documents)
    metadata["datasets"] = sorted(merged["groups"])
    return merged


def _font(path):
    from matplotlib import font_manager, rcParams
    candidates = [Path(path)] if path else [Path("C:/Windows/Fonts/msyh.ttc"), Path("C:/Windows/Fonts/simhei.ttf"),
        Path("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc")]
    chosen = next((candidate for candidate in candidates if candidate.is_file()), None)
    if chosen is None:
        raise ValueError("A CJK font file is required; pass --font-path")
    font_manager.fontManager.addfont(str(chosen))
    family = font_manager.FontProperties(fname=str(chosen)).get_name()
    rcParams.update({"font.family": family, "axes.unicode_minus": False, "svg.fonttype": "none"})
    return {"path": str(chosen.resolve()), "family": family, "sha256": _sha(chosen)}


def _confusion(dataset, groups):
    figure, axes = canvas(f"{dataset.upper()} · F6 二分类混淆矩阵", 8, columns=4)
    rows = []
    for axis, group in zip(axes, GROUPS, strict=True):
        confusion = get(groups.get(group, {}), "classification.binary.confusion")
        axis.set_title(group, loc="left")
        labels = ("attack", "benign", "unknown", "failed", "missing")
        if not isinstance(confusion, dict):
            axis.text(.5, .5, "N/A", ha="center", transform=axis.transAxes)
            axis.set_axis_off()
            for truth in ("attack", "benign"):
                for predicted in labels:
                    rows.append(record(dataset, group, f"{truth}.{predicted}", None, unit="count"))
            continue
        matrix = [[confusion.get(truth, {}).get(predicted, 0) for predicted in labels] for truth in ("attack", "benign")]
        axis.imshow(matrix, cmap="Blues", vmin=0, vmax=max([max(row) for row in matrix] + [1]), aspect="auto")
        for i, truth in enumerate(("attack", "benign")):
            denominator = sum(matrix[i])
            for j, predicted in enumerate(labels):
                value = matrix[i][j]
                rows.append(record(dataset, group, f"{truth}.{predicted}", value, denominator, unit="count"))
                axis.text(j, i, str(value), ha="center", va="center", fontsize=9,
                          color="white" if value > max([max(row) for row in matrix] + [1]) / 2 else "#333333")
        axis.set_yticks((0, 1), [f"攻击 n={sum(matrix[0])}", f"正常 n={sum(matrix[1])}"], fontsize=8)
        axis.set_xticks(range(5), ("攻击", "正常", "未知", "失败", "缺失"), rotation=35, ha="right", fontsize=8)
    return figure, rows, "金标两行；预测attack/benign/unknown，诊断失败与missing另列。每行显示完整适用分母，不删除未答。"


def _six(dataset, groups):
    from evals.metrics.classification import SIX_CLASSES
    figure, axes = canvas("AIT · F7 固定六类 F1 明细", 6, columns=3)
    rows = []
    for axis, label in zip(axes, SIX_CLASSES, strict=True):
        panel, notes = [], []
        for group in GROUPS[:4]:
            score = get(groups.get(group, {}), f"classification.six_class.per_class.{label}", {})
            denominator = get(groups.get(group, {}), "classification.six_class.applicable_n")
            value = score.get("f1") if denominator else None
            rows.append(record(dataset, group, label, value, score.get("support"), note="分母为该类金标支持数；固定六类平均保留零支持类"))
            panel.append(value)
            notes.append(f"支持={score.get('support', 'N/A')}")
        bars(axis, GROUPS[:4], panel, label.replace("_", "\n"), bounds=(0, 1.14), notes=notes)
    return figure, rows, "仅AIT；六类F1及每类支持数。零金标零预测类F1=0并保留固定六类平均，同时公开支持类平均。"


BUILDERS = (("baseline_quality", baseline.build), ("ablation_delta", ablation.build),
            ("evidence_quality", evidence.build), ("resource_cost", resources.build),
            ("coverage_status", coverage.build), ("binary_confusion", _confusion))


def generate_bundle(score_path, output_root, *, font_path=None):
    if isinstance(score_path, (list, tuple)):
        scores = merge_scores(score_path)
        inputs = scores["merged_inputs"]
        score_bytes = (json.dumps(scores, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    else:
        score_path = Path(score_path).resolve()
        score_bytes = score_path.read_bytes()
        scores = json.loads(score_bytes.decode("utf-8-sig"))
        inputs = [{"path": str(score_path), "sha256": hashlib.sha256(score_bytes).hexdigest()}]
    input_sha256 = hashlib.sha256(score_bytes).hexdigest()
    run_id = scores.get("run_id")
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", run_id):
        raise ValueError("Unsafe or missing run_id")
    root = Path(output_root).resolve() / run_id
    existing_manifest = root / "figure_manifest.json"
    if existing_manifest.exists() and json.loads(existing_manifest.read_text(encoding="utf-8"))["input_sha256"] != input_sha256:
        raise ValueError("Conflicting frozen score input for existing run outputs; choose a fresh output root")
    if root.exists() and any(root.iterdir()) and not existing_manifest.exists():
        raise ValueError("Conflicting unbound existing run outputs; choose a fresh output root")
    # Keep all caches in the task workspace when the sandboxed home is read-only.
    os.environ.setdefault("MPLCONFIGDIR", str(Path(output_root).resolve() / ".matplotlib-cache"))
    from matplotlib import __version__
    from matplotlib import pyplot as plt
    font = _font(font_path)
    root.mkdir(parents=True, exist_ok=True)
    metadata = scores.get("metadata", {})
    version_text = json.dumps(metadata, ensure_ascii=False, sort_keys=True)
    entries = []
    for dataset in ("ait", "dedale"):
        groups = scores.get("groups", {}).get(dataset, {})
        directory = root / dataset
        directory.mkdir(exist_ok=True)
        builders = list(BUILDERS)
        if dataset == "ait":
            builders.append(("six_class_f1", _six))
        builders.append(("verification_effect", lambda data, unused: verification.build(data, scores.get("verification", {}).get(data, {}))))
        for name, builder in builders:
            figure, records, explanation = builder(dataset, groups)
            computed = sum(number(row["value"]) for row in records)
            status = "no_computable_data" if not computed else "complete" if computed == len(records) else "partial"
            caption = (f"{dataset.upper()} / {name}\nrun_id={run_id}\n模型/系统版本：{version_text or '未提供'}\n"
                       f"{explanation}\n状态：{status}。缺失/N/A不是零；空图不能证明实验完成。"
                       "\n指标方向与有效分母逐行见同名CSV。无显著性星号或无依据置信区间。\n")
            finish(figure, f"run={run_id} · {status} · {explanation[:90]}")
            paths = {"png": directory / f"{name}.png", "svg": directory / f"{name}.svg",
                     "csv": directory / f"{name}.csv", "caption": directory / f"{name}.txt"}
            figure.savefig(paths["png"], dpi=300, facecolor="white")
            figure.savefig(paths["svg"], facecolor="white")
            plt.close(figure)
            with paths["csv"].open("w", encoding="utf-8-sig", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
                writer.writeheader()
                writer.writerows(records)
            paths["caption"].write_text(caption, encoding="utf-8")
            entries.append({"dataset": dataset, "figure": name, "status": status,
                            "computed_values": computed, "table_rows": len(records),
                            "outputs": {kind: {"path": path.relative_to(root).as_posix(), "sha256": _sha(path)}
                                        for kind, path in paths.items()}})
    sources = {path.name: _sha(path) for path in Path(__file__).parent.glob("*.py")}
    if any(_sha(item["path"]) != item["sha256"] for item in inputs):
        raise ValueError("Frozen score input changed during plotting")
    manifest = {"schema_version": 1, "run_id": run_id, "input_sha256": input_sha256, "inputs": inputs,
                "source_hashes": scores.get("source_hashes", {}), "metadata": metadata,
                "matplotlib_version": __version__, "font": font, "plot_source_sha256": sources,
                "configuration": {"version": "task13-figures-v1", "dpi": 300, "minimum_width_px": 1800,
                                  "group_order": list(GROUPS), "delta": "100*(ablation-B3)",
                                  "semantic_scope": "human sample only"},
                "not_applicable": [{"dataset": "dedale", "figure": "six_class_f1", "reason": "Frozen six_class mask is false"}],
                "status": "complete" if all(entry["status"] == "complete" for entry in entries) else "incomplete",
                "figures": entries}
    (root / "figure_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scores", required=True, action="append", help="Repeat for separately frozen AIT and DEDALE summaries")
    parser.add_argument("--output-root", default="data/task13/figures")
    parser.add_argument("--font-path")
    args = parser.parse_args()
    source = args.scores[0] if len(args.scores) == 1 else args.scores
    manifest = generate_bundle(source, args.output_root, font_path=args.font_path)
    print(json.dumps({"run_id": manifest["run_id"], "status": manifest["status"], "figures": len(manifest["figures"])}, ensure_ascii=False))


if __name__ == "__main__":
    main()
