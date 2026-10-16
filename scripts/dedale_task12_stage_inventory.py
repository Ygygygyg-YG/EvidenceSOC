"""Prepare scoring-only DEDALE evidence for an independent stage review.

The packet is deliberately incomplete. Official malicious membership and
process lifecycles establish review inputs, never an event's tactic. No model
is invoked, no agent artifact is changed, and the CLI only creates a new file
under the supplied scoring-source directory.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import quote
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evals.datasets.dedale.build_manifests import project_observations, utc
from evals.datasets.dedale.common import (
    canonical,
    is_hash,
    read_json,
    safe_file,
    sha256,
    write_new,
)
from evals.datasets.dedale.join_labels import (
    LABEL_MEMBERS,
    canonical_event_fingerprint,
    load_label_index,
)
from evals.datasets.dedale.parse import parse_event

PINNED_COMMIT = "f148722eb5908fc17841dc3c8be1591c5c3e59a6"
PINNED_PROVENANCE_SHA256 = "6143785a24dfc9712f4d76563fbc4217ebdb4c7c8489fe8829b240ca77c91bc4"
PINNED_STAGE_HTML_SHA256 = "bfa5a0be334d4113f4fdef9e1499fce025a510454c877e08628aa333596a3295"
STAGE_URL = "https://dedale.inria.fr/attack_scenario.html"
STAGES = (
    "initial_access", "execution", "persistence", "command_and_control",
    "discovery", "lateral_movement", "collection", "exfiltration",
)
CSV_NAMES = {
    "gt_internalserver_class_1.csv", "gt_internalserver_class_1_and_2.csv",
    "gt_internalserver_presentation_pdf_class_1.csv",
    "gt_windows_client1_class_1.csv", "gt_windows_client1_class_1_and_2.csv",
    "gt_windows_client2_class_1.csv", "gt_windows_client2_class_1_and_2.csv",
}
SOURCE_FILES = {"system_log_labeling/ground_truth/" + name for name in CSV_NAMES} | {
    f"system_log_labeling/{prefix}_{source}/src/main.rs"
    for prefix in ("label_dedale", "pid_tree_dedale")
    for source in ("auditbeat", "winlogbeat")
}
ARTIFACTS = {
    "agent/events.jsonl", "agent/manifest.json", "scoring/gold.jsonl",
    "scoring/source-gold.json", "scoring/manifest.json",
}
PROVENANCE_FIELDS = (
    "archive", "relative_log_path", "line_number", "raw_line_sha256", "event_fingerprint",
)


def _json_object(raw: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def nonfinite(value):
        raise ValueError("nonfinite JSON value")

    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=nonfinite)
    if not isinstance(value, dict):
        raise ValueError("evidence JSON must be an object")  # noqa: TRY004 - invalid external evidence
    canonical(value)
    return value


def _jsonl(path: Path) -> list[dict]:
    with path.open("rb") as stream:
        return [_json_object(raw) for raw in stream]


def _review_sources(root: Path) -> tuple[dict, list[dict]]:
    """Anchor local source bytes to the previously acquired fixed revision."""
    provenance_path = safe_file(root, "provenance.json")
    if sha256(provenance_path) != PINNED_PROVENANCE_SHA256:
        raise ValueError("scoring source provenance SHA256 differs from pinned acquisition")
    provenance = read_json(provenance_path)
    commit = read_json(safe_file(root, "commit.json"))
    if provenance.get("resolved_commit") != PINNED_COMMIT or commit.get("id") != PINNED_COMMIT:
        raise ValueError("scoring source does not identify the fixed official commit")
    files = provenance.get("files", [])
    if len(files) != len(SOURCE_FILES) or {row["path"] for row in files} != SOURCE_FILES:
        raise ValueError("fixed scoring source inventory must contain seven CSVs and four Rust files")
    bindings, lifecycles = [], []
    for row in files:
        relative = row["path"]
        path = safe_file(root, "repository/" + relative)
        expected_url = (
            "https://gitlab.inria.fr/api/v4/projects/mlanvin%2Fdedale_labeling/repository/files/"
            + quote(relative, safe="") + "/raw?ref=" + PINNED_COMMIT
        )
        if row.get("url") != expected_url:
            raise ValueError("repository source URL is not bound to fixed official commit")
        if not is_hash(row.get("sha256")) or sha256(path) != row["sha256"] or path.stat().st_size != row["bytes"]:
            raise ValueError("repository source SHA256 or byte count mismatch")
        bindings.append({"path": "repository/" + relative, "sha256": row["sha256"], "url": row["url"]})
        if path.suffix != ".csv":
            continue
        with path.open(encoding="utf-8", newline="") as stream:
            for line_number, fields in enumerate(csv.reader(stream), 1):
                if not fields:
                    continue
                windows = "windows" in path.name
                if len(fields) != (5 if windows else 4):
                    raise ValueError("unexpected fixed lifecycle CSV schema")
                host, *identity, start, end = fields
                entity, pid = identity if windows else (None, identity[0])
                if not pid.isdecimal() or utc(start) > utc(end):
                    raise ValueError("invalid official process lifecycle")
                lifecycles.append({
                    "source_path": "repository/" + relative, "source_sha256": row["sha256"],
                    "source_url": row["url"], "line_number": line_number,
                    "source": "winlogbeat" if windows else "auditbeat", "host": host,
                    "entity_id": entity, "pid": int(pid), "create_timestamp": start,
                    "terminate_timestamp": end, "candidate_only": True,
                })
    catalog = read_json(safe_file(root, "stage-review-catalog.json"))
    stage_source = catalog.get("official_stage_source", {})
    if (catalog.get("fixed_ground_truth_commit") != PINNED_COMMIT
            or len(catalog.get("stages", [])) != len(STAGES)
            or {row["stage"] for row in catalog["stages"]} != set(STAGES)
            or stage_source != {"url": STAGE_URL, "sha256": PINNED_STAGE_HTML_SHA256}
            or sha256(safe_file(root, "site/attack_scenario.html")) != PINNED_STAGE_HTML_SHA256):
        raise ValueError("official stage source SHA256 or review vocabulary mismatch")
    timeline = read_json(safe_file(root, "site/attack-timeline.json"))
    if timeline.get("source_url") != STAGE_URL or timeline.get("sha256") != PINNED_STAGE_HTML_SHA256:
        raise ValueError("official timeline is not bound to the pinned scenario page")
    for relative in ("provenance.json", "commit.json", "stage-review-catalog.json", "site/attack_scenario.html", "site/attack-timeline.json"):
        bindings.append({"path": relative, "sha256": sha256(safe_file(root, relative))})
    return {"fixed_commit": PINNED_COMMIT, "bindings": bindings, "timeline": timeline}, lifecycles


def _original_labels(path: Path, index) -> dict:
    """Retain complete source events only in memory for the scoring packet."""
    result = {}
    with ZipFile(path) as archive:
        for member, (source, _) in LABEL_MEMBERS.items():
            with archive.open(member) as stream:
                for line_number, raw in enumerate(stream, 1):
                    event = _json_object(raw)
                    fingerprint = canonical_event_fingerprint(event)
                    key = source, fingerprint
                    entry = index.entries.get(key)
                    if entry is None or entry["host"] != event["host"]["name"]:
                        raise ValueError("original label fingerprint does not match official label membership")
                    record = result.setdefault(key, {"raw_event": event, "locations": []})
                    if record["raw_event"] != event:
                        raise ValueError("conflicting original label event fingerprint")
                    record["locations"].append({
                        "archive_member": member, "line_number": line_number,
                        "label_raw_line_sha256": hashlib.sha256(raw).hexdigest(),
                    })
    if result.keys() != index.entries.keys():
        raise ValueError("incomplete original official label membership")
    return result


def _lifecycle_candidates(event: dict, lifecycles: list[dict]) -> list[dict]:
    """A lifecycle match cannot supply a tactic, parent link or causal claim."""
    source = event["agent"]["type"]
    host = event["host"]["name"]
    process = event.get("process") or {}
    if not isinstance(process, dict):
        process = {}
    identities = [("process.pid", process.get("pid"))]
    winlog = event.get("winlog") or {}
    native_process = winlog.get("process", {}) if isinstance(winlog, dict) else {}
    if isinstance(native_process, dict):
        identities.append(("winlog.process.pid", native_process.get("pid")))
    timestamp = utc(event["@timestamp"])
    matches = []
    for lifecycle in lifecycles:
        expected_host = lifecycle["host"] + ".breach.local" if source == "winlogbeat" else lifecycle["host"]
        if source != lifecycle["source"] or host != expected_host:
            continue
        if not utc(lifecycle["create_timestamp"]) <= timestamp <= utc(lifecycle["terminate_timestamp"]):
            continue
        entity = process.get("entity_id")
        if entity is not None and lifecycle["entity_id"] is not None and entity != lifecycle["entity_id"]:
            continue
        matched = [field for field, pid in identities
                   if type(pid) is int and pid == lifecycle["pid"]]
        if entity is not None and entity == lifecycle["entity_id"]:
            matched.append("process.entity_id")
        if matched:
            matches.append({**lifecycle, "matched_fields": matched,
                            "reason": "Source, host, native process identity and lifecycle time overlap; no stage assignment."})
    return matches


def _verify_selection(selection: dict) -> list[dict]:
    cases = selection.get("cases", [])
    if (selection.get("dataset_id") != "dedale-v2.1"
            or selection.get("official_label_archive_verified") is not True
            or not cases or selection.get("N_D") != len(cases) or selection.get("M_D") != len(cases)):
        raise ValueError("selection is not a nonempty official-label selected dataset")
    identifiers = [row["case_id"] for row in cases]
    selected_ledger = [row.get("case_id") for row in selection.get("candidate_ledger", [])
                       if row.get("reason", "").startswith("selected_")]
    if (len(set(identifiers)) != len(identifiers)
            or selection.get("ablation_case_ids") != sorted(identifiers)
            or sorted(selected_ledger) != sorted(identifiers)):
        raise ValueError("selection case closure or identity mismatch")
    return cases


def build_inventory(*, cases_root: Path, data_root: Path, scoring_source_root: Path) -> dict:
    """Validate actual bytes before assembling an unsigned, incomplete packet."""
    cases_root, data_root, scoring_source_root = map(Path, (cases_root, data_root, scoring_source_root))
    selection_path = safe_file(cases_root, "selection.json")
    selection_file_sha256 = sha256(selection_path)
    selection = read_json(selection_path)
    cases = _verify_selection(selection)
    labels_path = safe_file(data_root, "system_logs_labels.zip")
    label_sha256 = sha256(labels_path)
    if selection.get("input_sha256", {}).get("archive:system_logs_labels.zip") != label_sha256:
        raise ValueError("official label archive SHA256 binding differs from selection")
    index = load_label_index(labels_path, exhaustive=True)
    if index.official_verified is not True:
        raise ValueError("official label archive integrity verification failed")
    source_context, lifecycles = _review_sources(scoring_source_root)
    originals = _original_labels(labels_path, index)
    bindings, selected, counts = [], [], Counter()
    for case in cases:
        if case.get("split") != "test" or set(case.get("artifacts", {})) != ARTIFACTS:
            raise ValueError("selected case artifact SHA256 inventory is incomplete")
        case_root = safe_file(cases_root, "test/" + case["case_id"])
        for relative, expected in sorted(case["artifacts"].items()):
            path = safe_file(case_root, relative)
            actual = sha256(path)
            if not is_hash(expected) or actual != expected:
                raise ValueError("selected artifact SHA256 mismatch: " + relative)
            bindings.append({"case_id": case["case_id"], "path": relative, "sha256": actual})
        events = _jsonl(case_root / "agent/events.jsonl")
        gold = _jsonl(case_root / "scoring/gold.jsonl")
        agent = read_json(case_root / "agent/manifest.json")
        score = read_json(case_root / "scoring/manifest.json")
        expected_artifacts = {key: value for key, value in case["artifacts"].items() if key != "scoring/manifest.json"}
        if (agent.get("case_id") != case["case_id"]
                or agent.get("events_sha256") != case["artifacts"]["agent/events.jsonl"]
                or score.get("case_id") != case["case_id"]
                or score.get("artifacts") != expected_artifacts
                or score.get("input_sha256") != selection.get("input_sha256")):
            raise ValueError("selected case manifest binding mismatch")
        if (not events or len(events) > 100 or len(events) != len(gold)
                or len(events) != case["event_count"]
                or len({event["external_id"] for event in events}) != len(events)):
            raise ValueError("selected event/gold count or identity mismatch")
        if (case.get("is_attack") is not any(row.get("source_label") == "malicious" for row in gold)
                or score.get("case_is_attack") is not case.get("is_attack")):
            raise ValueError("selected case attack decision mismatch")
        for observation, truth in zip(events, gold, strict=True):
            provenance = {key: observation[key] for key in PROVENANCE_FIELDS}
            fingerprint, source = observation["event_fingerprint"], observation["source"]
            if (truth.get("external_id") != observation["external_id"]
                    or truth.get("provenance") != provenance
                    or not is_hash(fingerprint) or not is_hash(observation["raw_line_sha256"])
                    or observation != project_observations(observation)
                    or observation["host"] != case["host"]
                    or observation["dataset_id"] != "dedale-v2.1:" + case["case_id"]
                    or not utc(case["time_from"]) <= utc(observation["observed_at"]) < utc(case["time_to"])):
                raise ValueError("selected gold fingerprint, provenance or observation scope mismatch")
            label = index.classify(source, fingerprint, host=observation["host"])
            if label != truth.get("source_label"):
                raise ValueError("selected gold contradicts official label membership")
            decision = {"malicious": True, "benign": False, "malicious-related": None, "unscorable": None}[label]
            if truth.get("is_attack") is not decision or truth.get("attack_types") != []:
                raise ValueError("selected gold changes official label semantics")
            original = originals.get((source, fingerprint))
            candidates = []
            label_record = None
            if original is not None:
                raw = original["raw_event"]
                expected_projection = parse_event((canonical(raw) + "\n").encode(),
                    archive=observation["archive"], relative_log_path=observation["relative_log_path"],
                    line_number=observation["line_number"])
                # The label archive contains the original source object, not
                # the system archive's byte serialization or optional ES _id.
                for field in ("dataset_id", "raw_line_sha256", "source_event_id"):
                    expected_projection[field] = observation[field]
                if project_observations(expected_projection) != observation:
                    raise ValueError("selected observation differs from original label projection")
                label_record = {"source": source, "event_fingerprint": fingerprint,
                                "source_label": label, **original}
                candidates = _lifecycle_candidates(raw, lifecycles)
            counts[label] += 1
            selected.append({"case_id": case["case_id"], "external_id": observation["external_id"],
                             "gold": truth, "observation": observation,
                             "original_label": label_record, "process_lifecycle_candidates": candidates})
    if sha256(selection_path) != selection_file_sha256:
        raise ValueError("selection changed while reading")
    for binding in bindings:
        path = safe_file(cases_root, "test/" + binding["case_id"] + "/" + binding["path"])
        if sha256(path) != binding["sha256"]:
            raise ValueError("selected artifact SHA256 changed while reading")
    for binding in source_context["bindings"]:
        if sha256(safe_file(scoring_source_root, binding["path"])) != binding["sha256"]:
            raise ValueError("scoring source SHA256 changed while reading")
    if sha256(labels_path) != label_sha256:
        raise ValueError("official label archive SHA256 changed while reading")
    return {
        "schema_version": 1, "dataset_id": "dedale-v2.1", "complete": False,
        "review_status": "pending_independent_review", "reviewer": None,
        "selection_sha256": hashlib.sha256((canonical(selection) + "\n").encode()).hexdigest(),
        "selection_file_sha256": selection_file_sha256, "input_sha256": selection["input_sha256"],
        "official_label_archive_sha256": label_sha256,
        "artifact_bindings": bindings, "source_context": source_context,
        "statistics": {"selected_cases": len(cases), "selected_events": len(selected),
                       "selected_source_labels": dict(sorted(counts.items())),
                       "selected_original_label_events": sum(row["original_label"] is not None for row in selected)},
        "stages": [{"stage": stage, "basis_url": STAGE_URL, "observable": None,
                    "reason": "Pending independent review of the selected original actions and causal process evidence.",
                    "evidence": [], "review_status": "not_reviewed"} for stage in STAGES],
        "evidence_policy": {
            "time_overlap": "candidate context only; the website schedule has no stated timezone",
            "process_lifecycle": "candidate context only; no tactic labels or causal parent links in CSVs",
            "stage_assignment": "requires independent action or causal-chain review tied to selected malicious gold",
            "unobservable": "record a source-based reason rather than inventing stage or ATT&CK gold",
            "automatic_review_signature": False,
        },
        "selected_events": selected,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("cases-root", "data-root", "scoring-source-root", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args(argv)
    source_root = args.scoring_source_root.absolute()
    safe_file(source_root, "provenance.json")
    output = args.output.absolute()
    try:
        relative = output.relative_to(source_root).as_posix()
        checked_output = safe_file(source_root, relative)
    except ValueError as exc:
        raise ValueError("review output must stay inside the scoring-source root") from exc
    safe_file(args.cases_root, "selection.json")
    if checked_output.resolve().is_relative_to(args.cases_root.resolve()):
        raise ValueError("review output must not enter the selected case tree")
    if checked_output.exists():
        raise FileExistsError("review packet already exists; preserve prior review")
    report = build_inventory(cases_root=args.cases_root, data_root=args.data_root,
                             scoring_source_root=source_root)
    write_new(checked_output, report)
    print(canonical({"complete": False, "review_status": report["review_status"],
                     "selection_sha256": report["selection_sha256"], "statistics": report["statistics"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
