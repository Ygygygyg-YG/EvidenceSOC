"""Audit frozen Task 11 test packs for split, leakage, and rebuild invariants."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime
from itertools import pairwise
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_FIELDS = {
    "labels",
    "rules",
    "dataset_labels",
    "annotation_status",
    "is_attack",
    "attack_types",
    "mapping_evidence",
    "unmapped_labels",
    "taxonomy_version",
    "normal_basis",
    "source_gold",
    "expected_answer",
    "attacks_log",
    "attacker_config",
}
FORBIDDEN_LITERALS = (
    b"attacker_0",
    b"attacks.log",
    b"attacker_config",
    b"expected_answer",
)
ARTIFACTS = (
    "agent/events.jsonl",
    "agent/manifest.json",
    "scoring/gold.jsonl",
    "scoring/source-gold.json",
    "scoring/manifest.json",
)
PROFILES = ("apache", "intranet-audit", "dnsmasq")


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def has_forbidden_field(value) -> bool:
    if isinstance(value, dict):
        return any(
            key in FORBIDDEN_FIELDS or has_forbidden_field(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(has_forbidden_field(child) for child in value)
    return False


def global_attack_bins(scenario: str) -> set[datetime]:
    root = ROOT / "data/ait/scenarios" / scenario / "processed"
    bins = set()
    for profile in PROFILES:
        events = root / "agent" / f"{scenario}-{profile}-events.jsonl"
        scored = root / "gold" / f"{scenario}-{profile}-scored-gold.jsonl"
        with events.open("rb") as agent, scored.open("rb") as gold:
            for eraw, graw in zip(agent, gold, strict=True):
                if json.loads(graw)["is_attack"] is True:
                    observed = json.loads(eraw)["observed_at"]
                    instant = datetime.fromisoformat(observed.replace("Z", "+00:00"))
                    bins.add(
                        instant.replace(
                            minute=instant.minute // 10 * 10, second=0, microsecond=0
                        )
                    )
    return bins


def main() -> None:
    splits = json.loads(
        (ROOT / "data/manifests/ait-v2-splits.json").read_text(encoding="utf-8-sig")
    )
    sets = [set(rows) for rows in splits.values()]
    if any(
        sets[i] & sets[j] for i in range(len(sets)) for j in range(i + 1, len(sets))
    ):
        raise ValueError("scenario split leakage")
    selection = json.loads(
        (ROOT / "data/manifests/ait-task11-test-selection.json").read_text(
            encoding="utf-8"
        )
    )
    cases = selection["cases"]
    if selection["scenario_groups"] != ["shaw", "wilson"]:
        raise ValueError("unexpected test scenario groups")
    if len(cases) != selection["actual"]["N"]:
        raise ValueError("case count differs from freeze")
    if len({row["case_id"] for row in cases}) != len(cases):
        raise ValueError("duplicate case ID")
    membership = Counter()
    intervals = {scenario: [] for scenario in splits["test"]}
    attacked = {scenario: global_attack_bins(scenario) for scenario in splits["test"]}
    for row in cases:
        name = row["case_id"]
        scenario = row["scenario"]
        if scenario not in splits["test"] or not name.startswith(scenario + "-test-"):
            raise ValueError(f"case outside test split: {name}")
        start = datetime.fromisoformat(row["time_from"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(row["time_to"].replace("Z", "+00:00"))
        if not start < end:
            raise ValueError(f"invalid interval: {name}")
        if row["class"] == "normal" and start in attacked[scenario]:
            raise ValueError(
                f"normal window overlaps another reviewed attack source: {name}"
            )
        intervals[scenario].append((start, end, name))
        membership[row["class"]] += 1
        root = ROOT / "data/ait/cases/test" / name
        rebuilt = ROOT / "data/ait/rebuilds/test" / name
        if sorted(path.name for path in (root / "agent").iterdir()) != [
            "events.jsonl",
            "manifest.json",
        ]:
            raise ValueError(f"unexpected Agent artifact: {name}")
        for relative in ARTIFACTS:
            if hash_file(root / relative) != hash_file(rebuilt / relative):
                raise ValueError(f"rebuild artifact differs: {name}/{relative}")
        if hash_file(root / "scoring/manifest.json") != row["scoring_manifest_sha256"]:
            raise ValueError(f"scoring manifest hash differs: {name}")
        if hash_file(root / "agent/manifest.json") != row["agent_manifest_sha256"]:
            raise ValueError(f"Agent manifest hash differs: {name}")
        agent = json.loads((root / "agent/manifest.json").read_text(encoding="utf-8"))
        scoring = json.loads(
            (root / "scoring/manifest.json").read_text(encoding="utf-8")
        )
        if (
            agent["scenario"] != scenario
            or scoring["scenario"] != scenario
            or agent["split"] != "test"
            or scoring["split"] != "test"
            or scoring["counts"]["unknown"]
            or scoring["counts"]["selected"] != row["actual_count"]["selected"]
            or scoring["counts"]["attack"] != row["actual_count"]["attack"]
            or scoring["counts"]["normal"] != row["actual_count"]["normal"]
            or scoring["counts"]["attack"] != row["expected_count"].get("attack", 0)
            or scoring["counts"]["normal"] != row["expected_count"].get("normal", 0)
        ):
            raise ValueError(f"case metadata differs from freeze: {name}")
        if (row["class"] == "attack" and not scoring["counts"]["attack"]) or (
            row["class"] == "normal" and scoring["counts"]["attack"]
        ):
            raise ValueError(f"case class differs from freeze: {name}")
        if has_forbidden_field(agent):
            raise ValueError(f"ground truth in Agent manifest: {name}")
        count = 0
        with (root / "agent/events.jsonl").open("rb") as stream:
            for raw in stream:
                if any(term in raw.lower() for term in FORBIDDEN_LITERALS):
                    raise ValueError(f"ground-truth literal in Agent event: {name}")
                if has_forbidden_field(json.loads(raw)):
                    raise ValueError(f"ground-truth field in Agent event: {name}")
                count += 1
        if count != agent["event_count"] or count != scoring["counts"]["selected"]:
            raise ValueError(f"Agent event count differs from scoring: {name}")
    for scenario, rows in intervals.items():
        rows.sort()
        if any(previous[1] > current[0] for previous, current in pairwise(rows)):
            raise ValueError(f"overlapping test windows: {scenario}")
    if (
        membership["attack"] != selection["actual"]["attack"]
        or membership["normal"] != selection["actual"]["normal"]
        or len(selection["ablation_case_ids"]) != selection["actual"]["M"]
        or not set(selection["ablation_case_ids"]) <= {row["case_id"] for row in cases}
    ):
        raise ValueError("test or ablation count differs from freeze")
    print(
        json.dumps(
            {
                "case_count": len(cases),
                "attack": membership["attack"],
                "normal": membership["normal"],
                "ablation": selection["actual"]["M"],
                "nonoverlap": True,
                "agent_ground_truth_leakage": False,
                "all_rebuilds_identical": True,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
