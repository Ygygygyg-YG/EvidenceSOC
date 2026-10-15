"""Select non-overlapping AIT test phases and freeze rebuildable event packs.

Selection reads scoring gold locally; only the builder's Agent artifacts are
provided to the detection system. Multiple phases of one scenario remain
correlated and are never counted as independent scenarios.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from collections import Counter, defaultdict
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
BASE = ROOT / "evals" / "datasets" / "ait_v2"
SCENARIOS = ("shaw", "wilson")
PROFILES = ("apache", "intranet-audit", "dnsmasq")
ATTACK_PHASES = (
    ("dnsmasq", "reconnaissance", "dns-recon", 10, False),
    ("apache", "reconnaissance", "web-recon", 10, False),
    ("apache", "webshell_upload", "webshell-upload", 4, False),
    ("apache", "remote_command_execution", "remote-command", 5, False),
    ("intranet-audit", "privilege_escalation", "privilege-escalation", 25, True),
)
NORMAL_QUOTAS = {
    "shaw": {"apache": 2, "intranet-audit": 2, "dnsmasq": 1},
    "wilson": {"apache": 2, "intranet-audit": 2, "dnsmasq": 2},
}
MIN_NORMAL_GAP = timedelta(hours=2)
BUCKET_DURATION = timedelta(minutes=10)


def load_builder():
    spec = importlib.util.spec_from_file_location(
        "_ait_task11_case_builder", BASE / "build_manifests.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def profile_index(scenario: str, profile: str) -> dict:
    root = DATA / "ait" / "scenarios" / scenario / "processed"
    event_path = root / "agent" / f"{scenario}-{profile}-events.jsonl"
    gold_path = root / "gold" / f"{scenario}-{profile}-scored-gold.jsonl"
    seconds = defaultdict(Counter)
    buckets = defaultdict(Counter)
    first_by_type = {}
    type_seconds = defaultdict(Counter)
    count = 0
    with event_path.open("rb") as events, gold_path.open("rb") as scoring:
        for eraw, graw in zip(events, scoring, strict=True):
            event, answer = json.loads(eraw), json.loads(graw)
            instant = stamp(event["observed_at"])
            second = instant.replace(microsecond=0)
            bucket = instant.replace(
                minute=instant.minute // 10 * 10, second=0, microsecond=0
            )
            kind = "attack" if answer["is_attack"] is True else "normal"
            seconds[second][kind] += 1
            buckets[bucket][kind] += 1
            for attack_type in answer["attack_types"]:
                type_seconds[attack_type][second] += 1
                previous = first_by_type.get(attack_type)
                if previous is None or instant < previous:
                    first_by_type[attack_type] = instant
            count += 1
    return {
        "seconds": seconds,
        "buckets": buckets,
        "first": first_by_type,
        "type_seconds": type_seconds,
        "rows": count,
    }


def window_counts(index: dict, start: datetime, end: datetime) -> Counter:
    result = Counter()
    second = start.replace(microsecond=0)
    while second < end:
        result.update(index["seconds"].get(second, {}))
        second += timedelta(seconds=1)
    return result


def attack_case(scenario: str, indices: dict, spec: tuple) -> dict:
    profile, attack_type, phase, wanted_seconds, full_sources = spec
    type_seconds = indices[profile]["type_seconds"].get(attack_type)
    if not type_seconds:
        raise ValueError(f"missing reviewed attack phase: {scenario}/{phase}")
    profiles = PROFILES if full_sources else (profile,)
    best = None
    for start in sorted(type_seconds):
        for duration in range(wanted_seconds, 0, -1):
            end = start + timedelta(seconds=duration)
            total = sum(
                (window_counts(indices[p], start, end) for p in profiles), Counter()
            )
            if not total["attack"] or not 0 < total.total() <= 10000:
                continue
            target = sum(
                type_seconds.get(start + timedelta(seconds=offset), 0)
                for offset in range(duration)
            )
            score = (target, total["attack"], duration)
            if best is None or score > best[0]:
                best = (score, start, end, total)
            break
    if best is None:
        raise ValueError(f"no bounded attack window: {scenario}/{phase}")
    _, start, end, total = best
    return {
        "case_id": f"{scenario}-test-attack-{phase}",
        "scenario": scenario,
        "class": "attack",
        "phase": phase,
        "profiles": list(profiles),
        "time_from": iso(start),
        "time_to": iso(end),
        "expected_count": dict(total),
    }


def normal_cases(scenario: str, indices: dict, reserved: list) -> Iterator[dict]:
    chosen = []
    globally_attacked = {
        instant.replace(minute=instant.minute // 10 * 10, second=0, microsecond=0)
        for profile in PROFILES
        for instant, counts in indices[profile]["seconds"].items()
        if counts["attack"]
    }
    for profile, quota in NORMAL_QUOTAS[scenario].items():
        options = [
            start
            for start, counts in indices[profile]["buckets"].items()
            if start not in globally_attacked
            and counts["attack"] == 0
            and counts["normal"] >= 1
        ]
        options.sort()
        if not options:
            raise ValueError(f"no complete normal windows: {scenario}/{profile}")
        for slot in range(quota):
            candidates = options if slot == 0 else reversed(options)
            selected = next(
                (
                    start
                    for start in candidates
                    if all(abs(start - old) >= MIN_NORMAL_GAP for old in reserved)
                    and all(abs(start - old) >= MIN_NORMAL_GAP for old in chosen)
                ),
                None,
            )
            if selected is None:
                raise ValueError(
                    f"insufficient separated normal windows: {scenario}/{profile}"
                )
            chosen.append(selected)
            suffix = "early" if slot == 0 else "late"
            count = indices[profile]["buckets"][selected]
            reserved.append(selected)
            yield {
                "case_id": f"{scenario}-test-normal-{profile.replace('intranet-', '')}-{suffix}",
                "scenario": scenario,
                "class": "normal",
                "phase": f"{profile}-background-{suffix}",
                "profiles": [profile],
                "time_from": iso(selected),
                "time_to": iso(selected + BUCKET_DURATION),
                "expected_count": dict(count),
            }


def selection(scenarios: tuple[str, ...]) -> list[dict]:
    cases = []
    for scenario in scenarios:
        indices = {profile: profile_index(scenario, profile) for profile in PROFILES}
        phases = list(ATTACK_PHASES)
        if scenario == "wilson":
            phases.append(
                ("dnsmasq", "data_exfiltration", "dns-exfiltration", 10, False)
            )
        attack = [attack_case(scenario, indices, spec) for spec in phases]
        intervals = [(stamp(row["time_from"]), stamp(row["time_to"])) for row in attack]
        if any(
            a < d and c < b
            for i, (a, b) in enumerate(intervals)
            for c, d in intervals[i + 1 :]
        ):
            raise ValueError(f"attack phase windows overlap: {scenario}")
        reserved = [stamp(row["time_from"]) for row in attack]
        normal = list(normal_cases(scenario, indices, reserved))
        cases.extend(attack + normal)
    if len({row["case_id"] for row in cases}) != len(cases):
        raise ValueError("duplicate case IDs")
    return cases


def source_config(scenario: str, profiles: list[str]) -> Path:
    full = DATA / "manifests" / f"{scenario}-test-sources.json"
    if len(profiles) == len(PROFILES):
        return full
    profile = profiles[0]
    path = DATA / "manifests" / f"{scenario}-test-{profile}-sources.json"
    value = json.loads(full.read_text(encoding="utf-8"))
    name = profile.split("-")[-1]
    selected = [
        row
        for row in value["sources"]
        if (
            "apache"
            if "apache2/" in row["relative_log_path"]
            else "audit"
            if "/audit/" in row["relative_log_path"]
            else "dnsmasq"
        )
        == name
    ]
    if len(selected) != 1:
        raise ValueError(f"source profile not unique: {scenario}/{profile}")
    value["sources"] = selected
    if path.exists():
        if json.loads(path.read_text(encoding="utf-8")) != value:
            raise ValueError(f"source config differs: {path}")
    else:
        with path.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
    return path


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build(cases: list[dict], *, explicit_data_root=False) -> None:
    builder = load_builder()
    splits = DATA / "manifests" / "ait-v2-splits.json"
    for row in cases:
        config = source_config(row["scenario"], row["profiles"])
        data_root = builder.case_data_root(
            source_config=config, data_root=DATA, explicit=explicit_data_root
        )
        if data_root is not None:
            row["legacy_case_id"] = row["case_id"]
            row["case_id"] = builder.neutral_case_id(
                source_config=config,
                time_from=row["time_from"],
                time_to=row["time_to"],
            )
        output = DATA / "ait" / "cases" / "test" / row["case_id"]
        rebuilt = DATA / "ait" / "rebuilds" / "test" / row["case_id"]
        if not output.exists():
            result = builder.build_case(
                source_config=config,
                splits=splits,
                case_id=row["case_id"],
                time_from=row["time_from"],
                time_to=row["time_to"],
                output_dir=output,
                data_root=data_root,
            )
            print(row["case_id"], result["counts"]["selected"], flush=True)
        manifest = output / "scoring" / "manifest.json"
        value = json.loads(manifest.read_text(encoding="utf-8"))
        counts = value["counts"]
        if (
            value["split"] != "test"
            or counts["unknown"]
            or (row["class"] == "attack" and not counts["attack"])
            or (row["class"] == "normal" and counts["attack"])
            or counts["selected"] > 10000
        ):
            raise ValueError(f"invalid class, split, or bounds: {row['case_id']}")
        if not rebuilt.exists():
            builder.rebuild_case(
                manifest=manifest, output_dir=rebuilt, data_root=data_root
            )
        files = (
            "agent/events.jsonl",
            "agent/manifest.json",
            "scoring/gold.jsonl",
            "scoring/source-gold.json",
            "scoring/manifest.json",
        )
        if any(hash_file(output / path) != hash_file(rebuilt / path) for path in files):
            raise ValueError(f"rebuild differs: {row['case_id']}")
        row["actual_count"] = {
            "selected": counts["selected"],
            "attack": counts["attack"],
            "normal": counts["normal"],
            "unknown": counts["unknown"],
        }
        row["scoring_manifest_sha256"] = hash_file(manifest)
        row["agent_manifest_sha256"] = hash_file(output / "agent/manifest.json")
        row["rebuild_verified"] = True
    attacks = sorted(row["case_id"] for row in cases if row["class"] == "attack")
    normals = sorted(row["case_id"] for row in cases if row["class"] == "normal")
    subset = attacks[: min(12, len(attacks))] + normals[: min(12, len(normals))]
    report = {
        "schema_version": 1,
        "selection": "one bounded window per reviewed attack phase; separated 10-minute normal windows with no attack in any of the scenario's three reviewed sources",
        "split": "test",
        "scenario_groups": list(SCENARIOS),
        "same_scenario_windows_correlated": True,
        "target": {
            "attack": 24,
            "normal": 24,
            "ablation_attack": 12,
            "ablation_normal": 12,
        },
        "actual": {
            "attack": len(attacks),
            "normal": len(normals),
            "N": len(cases),
            "M": len(subset),
        },
        "shortfall_reason": "The two fixed AIT test scenarios have only a few distinct attack phases; slicing dense scans into extra windows would create correlated duplicates.",
        "ablation_case_ids": subset,
        "cases": sorted(cases, key=lambda row: row["case_id"]),
    }
    dest = DATA / "manifests" / "ait-task11-test-selection.json"
    if dest.exists():
        if json.loads(dest.read_text(encoding="utf-8")) != report:
            raise ValueError(f"frozen selection differs: {dest}")
    else:
        with dest.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print("frozen test selection", report["actual"], flush=True)


def main() -> None:
    global DATA
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--build", action="store_true")
    cli.add_argument("--scenarios", nargs="+", choices=SCENARIOS, default=SCENARIOS)
    cli.add_argument("--data-root", type=Path)
    args = cli.parse_args()
    DATA = args.data_root.resolve() if args.data_root is not None else DATA
    cases = selection(tuple(args.scenarios))
    for row in cases:
        print(row["case_id"], row["time_from"], row["time_to"], row["expected_count"])
    if args.build:
        if tuple(args.scenarios) != SCENARIOS:
            raise ValueError("freeze requires both fixed test scenarios")
        build(cases, explicit_data_root=args.data_root is not None)


if __name__ == "__main__":
    main()
