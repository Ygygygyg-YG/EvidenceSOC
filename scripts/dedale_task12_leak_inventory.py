"""Inventory annotation candidates in every final-selected public Agent file.

This creates unsigned evidence for independent review, never a freeze or an
acceptance decision. No model is called and no selected artifact is modified.
Commands, process names and other factual content remain exactly as observed.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evals.datasets.dedale.common import (
    canonical,
    is_hash,
    read_json,
    safe_file,
    sha256,
    write_new,
)
from evals.datasets.dedale.neutralize import PROTOCOL, instant, neutral_case_id
from scripts.dedale_task12_stage_inventory import _json_object

ARTIFACTS = frozenset({"agent/events.jsonl", "agent/manifest.json", "scoring/gold.jsonl",
                       "scoring/source-gold.json", "scoring/manifest.json"})
PUBLIC_FILES = frozenset({"agent/events.jsonl", "agent/manifest.json"})
# Exact expression used by scoring-source/annotation-leak-prereview.json.
ANNOTATION_REGEX = (
    r"(?i)(?:technique[_ .-]?(?:id|name)|tactic(?:[_ .-]?(?:id|name))?|"
    r"mitre(?:[._ :/-]?attack)?|attack\.mitre\.org|(?<![a-z0-9])T\d{4}(?:\.\d{3})?(?!\d))"
)
ATTACK_REGEX = r"(?i)att&ck"
RULE_KEY_REGEX = r"(?i)(?:^|[._])rule[_-]?name$"
MESSAGE_RULE_REGEX = r"(?im)^RuleName\s*:\s*([^\r\n]*)"
PATTERNS = (("annotation", re.compile(ANNOTATION_REGEX)), ("literal_attck", re.compile(ATTACK_REGEX)))
RULE_KEY = re.compile(RULE_KEY_REGEX)
MESSAGE_RULE = re.compile(MESSAGE_RULE_REGEX)
MAX_HITS = 1000
EXCERPT_LIMIT = 240
PATH_LIMIT = 512
PROVENANCE_FIELDS = ("archive", "relative_log_path", "line_number", "raw_line_sha256", "event_fingerprint")


def _require(condition, detail):
    if not condition:
        raise ValueError(detail)


def _object(path: Path) -> dict:
    value = read_json(path)
    _require(isinstance(value, dict), "selected JSON must be an object")
    canonical(value).encode("utf-8")  # Also reject float overflow and escaped lone surrogates.
    return value


def _jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open("rb") as stream:
        for raw in stream:
            _require(len(rows) < 100, "selected event/gold count exceeds 100")
            value = _json_object(raw)
            canonical(value).encode("utf-8")
            rows.append(value)
    return rows


def _selection_cases(selection: dict) -> tuple[list[dict], dict]:
    cases, ledger = selection.get("cases"), selection.get("candidate_ledger")
    _require(selection.get("protocol") == PROTOCOL and selection.get("dataset_id") == "dedale-v2.1"
             and selection.get("split") == "test" and selection.get("official_label_archive_verified") is True
             and selection.get("candidate_closure") is True, "invalid final selection protocol or closure")
    _require(isinstance(cases, list) and bool(cases) and all(isinstance(row, dict) for row in cases),
             "invalid selected case inventory")
    _require(all(type(selection.get(name)) is int and selection[name] == len(cases) for name in ("N_D", "M_D")),
             "selected case count mismatch")
    _require(isinstance(ledger, list) and all(isinstance(row, dict) for row in ledger), "invalid candidate ledger")
    identifiers = [case.get("case_id") for case in cases]
    _require(all(isinstance(value, str) and re.fullmatch(r"dedale-[0-9a-f]{16}", value) for value in identifiers)
             and len(set(identifiers)) == len(identifiers)
             and selection.get("ablation_case_ids") == sorted(identifiers), "selected case identity or ablation closure mismatch")
    selected = {}
    for row in ledger:
        reason = row.get("reason")
        if reason in {"selected_attack", "selected_normal"}:
            identifier = row.get("case_id")
            _require(isinstance(identifier, str) and identifier not in selected, "duplicate or missing selected ledger identity")
            selected[identifier] = row
        else:
            _require(row.get("case_id") is None and not (isinstance(reason, str) and reason.startswith("selected_")),
                     "unselected ledger entry carries a selected identity")
    _require(set(selected) == set(identifiers), "selected candidate ledger closure mismatch")
    counts = selection.get("counts", {})
    _require(isinstance(counts, dict) and all(type(counts.get(name)) is int and counts[name] >= 0
                                            for name in ("attack", "normal", "unscorable")), "invalid selected class counts")
    _require(all(type(case.get("is_attack")) is bool for case in cases), "invalid selected case attack identity")
    _require(counts["attack"] == sum(case["is_attack"] for case in cases)
             and counts["normal"] == sum(not case["is_attack"] for case in cases), "selected class count mismatch")
    inputs = selection.get("input_sha256")
    _require(isinstance(inputs, dict) and bool(inputs) and all(is_hash(value) for value in inputs.values()),
             "invalid selection input SHA256 inventory")
    for case in cases:
        row = selected[case["case_id"]]
        _require(case.get("split") == "test" and isinstance(case.get("host"), str)
                 and type(case.get("event_count")) is int and 1 <= case["event_count"] <= 100,
                 "invalid selected case count or scope")
        _require(row.get("host") == case["host"] and row.get("time_from") == case.get("time_from")
                 and row.get("time_to") == case.get("time_to")
                 and row.get("source") in {"auditbeat", "winlogbeat"}
                 and row.get("reason") == ("selected_attack" if case["is_attack"] else "selected_normal")
                 and row.get("candidate_kind") == ("attack" if case["is_attack"] else "control"),
                 "selected ledger identity or scope mismatch")
        _require(instant(case["time_from"]) < instant(case["time_to"])
                 and case["case_id"] == neutral_case_id(row["source"], case["host"], case["time_from"]),
                 "selected case neutral identity mismatch")
        artifacts = case.get("artifacts")
        _require(isinstance(artifacts, dict) and set(artifacts) == ARTIFACTS
                 and all(is_hash(value) for value in artifacts.values()), "selected artifact SHA256 inventory is incomplete")
        _require(case.get("agent_manifest_sha256") == artifacts["agent/manifest.json"]
                 and case.get("scoring_manifest_sha256") == artifacts["scoring/manifest.json"],
                 "selected case manifest SHA256 binding mismatch")
    return cases, selected


def _public_inventory(cases_root: Path, cases: list[dict]) -> None:
    test_root = safe_file(cases_root, "test")
    names = set()
    for path in test_root.iterdir():
        checked = safe_file(cases_root, "test/" + path.name)
        _require(checked.is_dir(), "selected case directory closure mismatch")
        names.add(path.name)
    _require(names == {case["case_id"] for case in cases}, "selected case directory closure mismatch")
    for case in cases:
        agent = safe_file(cases_root, "test/" + case["case_id"] + "/agent")
        actual = set()
        for path in agent.iterdir():
            checked = safe_file(agent, path.name)
            _require(checked.is_file(), "selected public file inventory contains an extra directory")
            actual.add("agent/" + path.name)
        _require(actual == PUBLIC_FILES, "selected public file inventory differs from manifest and events")


def _case_data(cases_root: Path, case: dict, row: dict, inputs: dict) -> tuple[dict, list[dict], list[dict]]:
    base = safe_file(cases_root, "test/" + case["case_id"])
    agent = _object(safe_file(base, "agent/manifest.json"))
    score = _object(safe_file(base, "scoring/manifest.json"))
    _object(safe_file(base, "scoring/source-gold.json"))
    events, gold = (_jsonl(safe_file(base, name)) for name in ("agent/events.jsonl", "scoring/gold.jsonl"))
    dataset = "dedale-v2.1:" + case["case_id"]
    _require(all(manifest.get("case_id") == case["case_id"] and manifest.get("dataset_id") == dataset
                 and manifest.get("split") == "test" for manifest in (agent, score)), "selected manifest identity mismatch")
    _require(agent.get("events_file") == "events.jsonl"
             and agent.get("events_sha256") == case["artifacts"]["agent/events.jsonl"]
             and type(agent.get("event_count")) is int and agent["event_count"] == case["event_count"]
             and agent.get("time_from") == case["time_from"] and agent.get("time_to") == case["time_to"]
             and agent.get("bounds") == "[start,end)" and type(agent.get("limit")) is int and agent["limit"] == 100
             and agent.get("filters") == {"host": case["host"], "dataset_id": dataset},
             "selected Agent manifest count, file or scope mismatch")
    _require(score.get("artifacts") == {key: value for key, value in case["artifacts"].items()
                                        if key != "scoring/manifest.json"}
             and score.get("input_sha256") == inputs and score.get("case_is_attack") is case["is_attack"],
             "selected scoring manifest binding mismatch")
    _require(len(events) == len(gold) == case["event_count"]
             and all(isinstance(event.get("external_id"), str) for event in events)
             and len({event["external_id"] for event in events}) == len(events), "selected event/gold count or identity mismatch")
    source_labels = Counter()
    for event, truth in zip(events, gold, strict=True):
        _require(re.fullmatch(r"dedale:[0-9a-f]{64}", event["external_id"]) is not None
                 and event.get("source") == row["source"] and event.get("host") == case["host"]
                 and event.get("dataset_id") == dataset
                 and instant(case["time_from"]) <= instant(event.get("observed_at")) < instant(case["time_to"]),
                 "selected event identity or scope mismatch")
        _require(truth.get("external_id") == event["external_id"]
                 and all(key in event for key in PROVENANCE_FIELDS)
                 and truth.get("provenance") == {key: event[key] for key in PROVENANCE_FIELDS},
                 "selected gold external_id or provenance pairing mismatch")
        label = truth.get("source_label")
        _require(isinstance(label, str) and label in {"malicious", "benign", "malicious-related", "unscorable"},
                 "invalid selected gold source label")
        source_labels[label] += 1
    _require(case["is_attack"] is bool(source_labels["malicious"])
             and (case["is_attack"] or set(source_labels) == {"benign"}), "selected case class pairing mismatch")
    _require(score.get("counts") == {"selected": len(gold), "attack": source_labels["malicious"],
                                    "normal": source_labels["benign"],
                                    "unknown": source_labels["malicious-related"] + source_labels["unscorable"]},
             "selected scoring manifest event count mismatch")
    return agent, events, gold


def _bounded(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    suffix = "...sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
    return value[:limit - len(suffix)] + suffix


def _scan_public(value, *, case: dict, file: str, state: dict, external_id=None) -> None:
    """Visit every key and string, even after the evidence excerpt cap is full."""
    def hit(rule, text, path, location, match_start=0, **extra):
        state["candidate_hits_total"] += 1
        if len(state["candidate_hits"]) < MAX_HITS:
            start = max(0, match_start - 60)
            state["candidate_hits"].append({
                "case_id": case["case_id"], "case_is_attack": case["is_attack"], "file": file,
                "external_id": external_id, "path": _bounded(path, PATH_LIMIT),
                "path_truncated": len(path) > PATH_LIMIT, "location": location, "rule": rule,
                "excerpt": text[start:start + EXCERPT_LIMIT], "value_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "review_status": "requires_manual_review", **extra,
            })

    def inspect(text, path, location):
        state["inspected_json_keys" if location == "json_key" else "inspected_string_values"] += 1
        for name, pattern in PATTERNS:
            match = pattern.search(text)
            if match is not None:
                hit(name, text, path, location, match.start())

    def rule_value(value, path, kind, **extra):
        text = value.strip() if isinstance(value, str) else canonical(value)
        state["rule_name_values"][_bounded(kind + ":" + text, EXCERPT_LIMIT)] += 1
        if text != "-":
            hit("rule_name_" + kind, text, path, "string_value" if isinstance(value, str) else "json_value", **extra)

    def visit(item, path):
        if isinstance(item, dict):
            for key, nested in item.items():
                child = path + "/" + key.replace("~", "~0").replace("/", "~1")
                inspect(key, child, "json_key")
                if RULE_KEY.search(key):
                    rule_value(nested, child, "structured")
                visit(nested, child)
        elif isinstance(item, list):
            for index, nested in enumerate(item):
                visit(nested, path + "/" + str(index))
        elif isinstance(item, str):
            inspect(item, path, "string_value")
            for match in MESSAGE_RULE.finditer(item):
                rule_value(match[1], path, "message", line_number=item.count("\n", 0, match.start()) + 1)

    visit(value, "")


def build_inventory(*, cases_root: Path) -> dict:
    """Bind the final selection, verify all five files, scan only public bytes."""
    cases_root = Path(cases_root)
    selection_path = safe_file(cases_root, "selection.json")
    selection_hash = sha256(selection_path)
    selection = _object(selection_path)
    cases, selected = _selection_cases(selection)
    _public_inventory(cases_root, cases)
    bindings = []
    # Hash the entire closed inventory before inspecting any content.
    for case in cases:
        for relative, expected in sorted(case["artifacts"].items()):
            path = safe_file(cases_root, "test/" + case["case_id"] + "/" + relative)
            actual = sha256(path)
            _require(actual == expected, "selected artifact SHA256 mismatch: " + relative)
            bindings.append({"case_id": case["case_id"], "path": relative, "sha256": actual})
    state = {"candidate_hits": [], "candidate_hits_total": 0, "inspected_json_keys": 0,
             "inspected_string_values": 0, "rule_name_values": Counter()}
    class_cases, class_events, labels = Counter(), Counter(), Counter()
    for case in cases:
        agent, events, gold = _case_data(cases_root, case, selected[case["case_id"]], selection["input_sha256"])
        kind = "attack" if case["is_attack"] else "normal"
        class_cases[kind] += 1
        class_events[kind] += len(events)
        labels.update(truth["source_label"] for truth in gold)
        _scan_public(agent, case=case, file="agent/manifest.json", state=state)
        for event in events:
            _scan_public(event, case=case, file="agent/events.jsonl", state=state, external_id=event["external_id"])
    _require(sha256(safe_file(cases_root, "selection.json")) == selection_hash, "selection changed while reading")
    for binding in bindings:
        path = safe_file(cases_root, "test/" + binding["case_id"] + "/" + binding["path"])
        _require(sha256(path) == binding["sha256"], "selected artifact SHA256 changed while reading")
    _public_inventory(cases_root, cases)
    return {
        "schema_version": 1, "dataset_id": "dedale-v2.1", "protocol": PROTOCOL,
        "complete": False, "scan_complete": True, "reviewer": None, "review_status": "pending_independent_review",
        "selection_file_sha256": selection_hash,
        "selection_sha256": hashlib.sha256((canonical(selection) + "\n").encode("utf-8")).hexdigest(),
        "input_sha256": selection["input_sha256"], "artifact_bindings": bindings,
        "public_file_bindings": [row for row in bindings if row["path"] in PUBLIC_FILES],
        "statistics": {
            "selected_cases": len(cases), "selected_events": sum(class_events.values()),
            "cases_by_class": {name: class_cases[name] for name in ("attack", "normal")},
            "events_by_case_class": {name: class_events[name] for name in ("attack", "normal")},
            "selected_source_labels": dict(sorted(labels.items())),
            "inspected_json_keys": state["inspected_json_keys"], "inspected_string_values": state["inspected_string_values"],
            "candidate_hits_total": state["candidate_hits_total"], "candidate_hits_recorded": len(state["candidate_hits"]),
            "candidate_hits_omitted": state["candidate_hits_total"] - len(state["candidate_hits"]),
        },
        "matching_rules": {"annotation_regex": ANNOTATION_REGEX, "literal_attck_regex": ATTACK_REGEX,
                           "rule_name_key_regex": RULE_KEY_REGEX, "message_rule_name_regex": MESSAGE_RULE_REGEX},
        "rule_name_values": dict(sorted(state["rule_name_values"].items())), "candidate_hits": state["candidate_hits"],
        "scope": {"all_selected_agent_manifests": True, "all_selected_agent_events": True,
                  "all_json_keys_and_string_values": True, "includes_attack_and_normal_cases": True,
                  "full_raw_archives_scanned": False, "model_invocations": 0},
        "evidence_policy": {
            "candidate_interpretation": "Independent review must distinguish publisher answer annotations from factual commands, process names, scripts and filenames; candidates are never automatically removed or relabeled.",
            "rule_name_hyphen": "A trimmed hyphen is benign; every other RuleName value requires manual review.",
            "candidate_count": "One candidate per matching rule and key/string, plus each non-hyphen RuleName occurrence; multiple matches in one string need not be separate candidates.",
            "recording_limits": {"candidate_hits": MAX_HITS, "excerpt_characters": EXCERPT_LIMIT, "path_characters": PATH_LIMIT},
            "limitations": "Pattern inspection does not establish universal semantic absence. This packet does not repeat source acquisition, raw scans, label verification or the final acceptance audit, and cannot sign an independent review or authorize freeze.",
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    safe_file(args.cases_root, "selection.json")
    output = args.output.absolute()
    output = safe_file(output.parent, output.name)
    _require(not output.resolve().is_relative_to(args.cases_root.resolve()),
             "review output must stay outside the selected case tree")
    if output.exists():
        raise FileExistsError("review packet already exists; preserve prior review")
    packet = build_inventory(cases_root=args.cases_root)
    # Check links again immediately before creating the exclusively new output.
    output = safe_file(output.parent, output.name)
    write_new(output, packet)
    print(canonical({"complete": False, "scan_complete": True, "review_status": packet["review_status"],
                     "selection_sha256": packet["selection_sha256"], "statistics": packet["statistics"]}))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, TypeError, RecursionError):
        print("Selected annotation inventory failed: invalid, changed or inaccessible input/output; no successful packet produced.", file=sys.stderr)
        raise SystemExit(1) from None
