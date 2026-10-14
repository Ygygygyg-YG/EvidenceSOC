"""Build and rebuild one attack and one normal pack for each new tune/validation scene."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "evals" / "datasets" / "ait_v2"
SCENARIOS = {
    "harrison": "development",
    "santos": "development",
    "wheeler": "development",
    "wardbeck": "validation",
}
ARTIFACTS = (
    "agent/events.jsonl",
    "agent/manifest.json",
    "scoring/gold.jsonl",
    "scoring/source-gold.json",
    "scoring/manifest.json",
)


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def source_config(scenario: str, split: str, profile: str | None) -> Path:
    full = ROOT / "data" / "manifests" / f"{scenario}-{split}-sources.json"
    if profile is None:
        return full
    if profile != "audit":
        raise ValueError(f"unsupported single-source profile: {profile}")
    path = ROOT / "data" / "manifests" / f"{scenario}-{split}-{profile}-sources.json"
    value = json.loads(full.read_text(encoding="utf-8"))
    source = [row for row in value["sources"] if "/audit/" in row["relative_log_path"]]
    if len(source) != 1:
        raise ValueError(f"missing source profile: {scenario}/{profile}")
    value["sources"] = source
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) != value:
            raise ValueError(f"existing source config differs: {path}")
    else:
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    return path


def windows(scenario: str) -> tuple[tuple[str, str], tuple[str, str]]:
    root = ROOT / "data" / "ait" / "scenarios" / scenario / "processed"
    apache_events = root / "agent" / f"{scenario}-apache-events.jsonl"
    apache_gold = root / "gold" / f"{scenario}-apache-scored-gold.jsonl"
    first_upload = None
    with apache_events.open("rb") as events, apache_gold.open("rb") as scored:
        for eraw, graw in zip(events, scored, strict=True):
            row = json.loads(graw)
            if "webshell_upload" in row["attack_types"]:
                first_upload = json.loads(eraw)["observed_at"]
                break
    if first_upload is None:
        raise ValueError(f"no reviewed upload phase: {scenario}")
    attack_start = datetime.fromisoformat(first_upload.replace("Z", "+00:00"))
    attack_start = attack_start.astimezone(UTC).replace(microsecond=0)
    audit_events = root / "agent" / f"{scenario}-intranet-audit-events.jsonl"
    audit_gold = root / "gold" / f"{scenario}-intranet-audit-scored-gold.jsonl"
    bins = {}
    with audit_events.open("rb") as events, audit_gold.open("rb") as scored:
        for eraw, graw in zip(events, scored, strict=True):
            event, row = json.loads(eraw), json.loads(graw)
            when = datetime.fromisoformat(event["observed_at"].replace("Z", "+00:00"))
            bucket = when.astimezone(UTC).replace(
                minute=when.minute // 10 * 10, second=0, microsecond=0
            )
            attack, normal = bins.get(bucket, (0, 0))
            bins[bucket] = (
                attack + (row["is_attack"] is True),
                normal + (row["is_attack"] is False),
            )
    globally_attacked = set()
    for profile in ("apache", "intranet-audit", "dnsmasq"):
        event_path = root / "agent" / f"{scenario}-{profile}-events.jsonl"
        scored_path = root / "gold" / f"{scenario}-{profile}-scored-gold.jsonl"
        with event_path.open("rb") as events, scored_path.open("rb") as scored:
            for eraw, graw in zip(events, scored, strict=True):
                if json.loads(graw)["is_attack"] is True:
                    observed = json.loads(eraw)["observed_at"]
                    when = datetime.fromisoformat(observed.replace("Z", "+00:00"))
                    globally_attacked.add(
                        when.astimezone(UTC).replace(
                            minute=when.minute // 10 * 10, second=0, microsecond=0
                        )
                    )
    normal_start = next(
        (
            t
            for t, (attack, normal) in sorted(bins.items())
            if not attack
            and normal
            and t not in globally_attacked
            and abs(t - attack_start) >= timedelta(hours=2)
        ),
        None,
    )
    if normal_start is None:
        raise ValueError(f"no separated normal audit window: {scenario}")
    iso = lambda t: t.isoformat().replace("+00:00", "Z")
    return (
        (iso(attack_start), iso(attack_start + timedelta(seconds=4))),
        (iso(normal_start), iso(normal_start + timedelta(minutes=10))),
    )


def main() -> None:
    builder = load("task11_dev_builder", BASE / "build_manifests.py")
    splits = ROOT / "data" / "manifests" / "ait-v2-splits.json"
    summary = []
    for scenario, split in SCENARIOS.items():
        attack, normal = windows(scenario)
        for number, klass, profile, bounds in (
            (1, "attack", None, attack),
            (2, "normal", "audit", normal),
        ):
            case_id = (
                f"{scenario}-{'dev' if split == 'development' else 'val'}-{number:03d}"
            )
            config = source_config(scenario, split, profile)
            output = ROOT / "data" / "ait" / "cases" / split / case_id
            rebuilt = ROOT / "data" / "ait" / "rebuilds" / split / case_id
            if not output.exists():
                builder.build_case(
                    source_config=config,
                    splits=splits,
                    case_id=case_id,
                    time_from=bounds[0],
                    time_to=bounds[1],
                    output_dir=output,
                )
            manifest = output / "scoring" / "manifest.json"
            value = json.loads(manifest.read_text(encoding="utf-8"))
            counts = value["counts"]
            if (
                value["split"] != split
                or counts["unknown"]
                or (klass == "attack" and not counts["attack"])
                or (klass == "normal" and counts["attack"])
            ):
                raise ValueError(f"case class/split mismatch: {case_id}")
            if not rebuilt.exists():
                builder.rebuild_case(manifest=manifest, output_dir=rebuilt)
            if any(
                digest(output / file) != digest(rebuilt / file) for file in ARTIFACTS
            ):
                raise ValueError(f"rebuild differs: {case_id}")
            summary.append(
                {
                    "case_id": case_id,
                    "split": split,
                    "class": klass,
                    "scenario": scenario,
                    "time_from": bounds[0],
                    "time_to": bounds[1],
                    "counts": {
                        "selected": counts["selected"],
                        "attack": counts["attack"],
                        "normal": counts["normal"],
                        "unknown": counts["unknown"],
                    },
                    "scoring_manifest_sha256": digest(manifest),
                    "rebuild_verified": True,
                }
            )
            print(case_id, summary[-1]["counts"], flush=True)
    dest = ROOT / "data" / "manifests" / "ait-task11-dev-validation-selection.json"
    value = {"schema_version": 1, "cases": summary}
    if dest.exists():
        if json.loads(dest.read_text(encoding="utf-8")) != value:
            raise ValueError(f"existing case selection differs: {dest}")
    else:
        with dest.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")


if __name__ == "__main__":
    main()
