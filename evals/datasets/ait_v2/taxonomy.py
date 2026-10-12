"""Verify reviewed AIT scenario annotations before generating scoring taxonomy."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "_ait_taxonomy_join", Path(__file__).with_name("join_labels.py")
)
assert _spec is not None and _spec.loader is not None
_join = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_join)
_parser = _join._parser
_object = _join._object
_audit_spec = importlib.util.spec_from_file_location(
    "_ait_taxonomy_audit", Path(__file__).with_name("audit_parse.py")
)
assert _audit_spec is not None and _audit_spec.loader is not None
_audit_parser = importlib.util.module_from_spec(_audit_spec)
_audit_spec.loader.exec_module(_audit_parser)
_DATASET = "ait-v2.1:fox"
_LOG = "intranet_server/logs/apache2/intranet.price.fox.org-access.log.2"
_OFFICIAL_MD5 = "27b09dd2876ec08ee99a9b53e8718c92"
_RUSSELL_DATASET = "ait-v2.1:russellmitchell"
_RUSSELL_LOG = (
    "intranet_server/logs/apache2/intranet.smith.russellmitchell.com-access.log.2"
)
_RUSSELL_OFFICIAL_MD5 = "abb43a46c70939ad9f98669e3510d2b7"
_EXTENDED_OFFICIAL_MD5 = {
    "ait-v2.1:harrison": "4e837053ce4c5496227e0a3b65048c1c",
    "ait-v2.1:santos": "cb484a2c55ea03c63c556f0531fe8367",
    "ait-v2.1:wardbeck": "14eeacd83571a83615c2cce1f6a6eacf",
    "ait-v2.1:wheeler": "774a146275a22707ee78bcb4574aca23",
    "ait-v2.1:shaw": "f890a1f52bc9f893b44254ad86118e39",
    "ait-v2.1:wilson": "98285593473dc05d0a6899f7cdefcd2d",
}
_EXTENDED_APACHE_LOGS = {
    "harrison": "intranet_server/logs/apache2/intranet.mannsmith.harrison.com-access.log.1",
    "santos": "intranet_server/logs/apache2/intranet.smith.santos.com-access.log",
    "wardbeck": "intranet_server/logs/apache2/intranet.hurstwong.wardbeck.info-access.log.1",
    "wheeler": "intranet_server/logs/apache2/intranet.flores.wheeler.biz-access.log.1",
    "shaw": "intranet_server/logs/apache2/intranet.thomasmurray.shaw.info-access.log.2",
    "wilson": "intranet_server/logs/apache2/intranet.hallbrown.wilson.com-access.log.2",
}
_VERSION = "fox-apache-taxonomy-v1"
_POLICY = "complete_official_annotation_absence"
ATTACK_TYPES = (
    "reconnaissance",
    "credential_attack",
    "webshell_upload",
    "remote_command_execution",
    "privilege_escalation",
    "data_exfiltration",
)
_PAIRS = {
    ("service_scan", "attacker.service_scan"): "reconnaissance",
    ("wpscan", "attacker.wpscan.time"): "reconnaissance",
    ("dirb", "attacker.dirb.time"): "reconnaissance",
    ("webshell_upload", "attacker.webshell.upload.seq"): "webshell_upload",
    ("webshell_cmd", "attacker.escalate.webshell.cmd.http"): "remote_command_execution",
    (
        "webshell_cmd",
        "attacker.escalate.webshell.cmd.http_prepare_crack",
    ): "remote_command_execution",
}
_AUDIT_LOG = "intranet_server/logs/audit/audit.log"
_AUDIT_VERSION = "fox-intranet-audit-taxonomy-v1"
_AUDIT_PAIRS = {
    (
        "escalated_sudo_command",
        "attacker.escalate.audit.sudo.command.start",
    ): "privilege_escalation",
    (
        "escalated_sudo_command",
        "attacker.escalate.audit.sudo.command.events",
    ): "privilege_escalation",
}
_DNS_LOG = "inet-firewall/logs/dnsmasq.log"
_DNS_VERSION = "fox-dnsmasq-taxonomy-v1"
_DNS_TIMESTAMP_PARAMETERS = {
    "year": 2022,
    "utc_offset": "+00:00",
    "basis": "explicit_year_and_utc_offset",
}
_DNS_PAIRS = {
    ("dnsteal", "dnsteal.domain.match"): "data_exfiltration",
    ("dnsteal-received", "dnsteal.domain.received"): "data_exfiltration",
    ("dns_scan", "attacker.foothold.dnsmasq.dns_scan_probe"): "reconnaissance",
    (
        "dns_scan",
        "attacker_foothold_dnsmasq_dns_brute_scan_parent_query",
    ): "reconnaissance",
    (
        "dns_scan",
        "attacker_foothold_dnsmasq_dns_brute_scan_sub_query",
    ): "reconnaissance",
    (
        "network_scan",
        "attacker_foothold_dnsmasq_nmap_scan_parent_query",
    ): "reconnaissance",
    ("network_scan", "attacker_foothold_dnsmasq_nmap_scan_sub_query"): "reconnaissance",
    (
        "service_scan",
        "attacker_foothold_dnsmasq_service_scan_parent_query",
    ): "reconnaissance",
    (
        "service_scan",
        "attacker_foothold_dnsmasq_service_scan_sub_query",
    ): "reconnaissance",
    ("traceroute", "attacker.foothold.dnsmasq.traceroute"): "reconnaissance",
    ("wpscan", "attacker.foothold.dnsmasq.wpscan"): "reconnaissance",
}
_dns_spec = importlib.util.spec_from_file_location(
    "_ait_taxonomy_dns", Path(__file__).with_name("dnsmasq_parse.py")
)
assert _dns_spec is not None and _dns_spec.loader is not None
_dns_parser = importlib.util.module_from_spec(_dns_spec)
_dns_spec.loader.exec_module(_dns_parser)


def _parse_dns_line(
    text, *, dataset_id, relative_log_path, line_number, raw_line_sha256
):
    return _dns_parser.parse_dnsmasq_line(
        text,
        dataset_id=dataset_id,
        relative_log_path=relative_log_path,
        line_number=line_number,
        raw_line_sha256=raw_line_sha256,
        year=2022,
        utc_offset="+00:00",
    )


_SCENARIOS = {
    _DATASET: {
        _LOG: (_VERSION, _PAIRS, _parser.parse_apache_line),
        _AUDIT_LOG: (_AUDIT_VERSION, _AUDIT_PAIRS, _audit_parser.parse_audit_line),
        _DNS_LOG: (_DNS_VERSION, _DNS_PAIRS, _parse_dns_line),
    },
    _RUSSELL_DATASET: {
        _RUSSELL_LOG: (
            "russellmitchell-apache-taxonomy-v1",
            dict(_PAIRS),
            _parser.parse_apache_line,
        ),
        _AUDIT_LOG: (
            "russellmitchell-intranet-audit-taxonomy-v1",
            {
                **_AUDIT_PAIRS,
                (
                    "attacker_change_user",
                    "attacker.escalate.audit.su.login",
                ): "privilege_escalation",
            },
            _audit_parser.parse_audit_line,
        ),
        _DNS_LOG: (
            "russellmitchell-dnsmasq-taxonomy-v1",
            {
                **_DNS_PAIRS,
                (
                    "dirb",
                    "attacker_foothold_dnsmasq_dirb_parent_query",
                ): "reconnaissance",
                ("dirb", "attacker_foothold_dnsmasq_dirb_sub_query"): "reconnaissance",
                # Dropped/retried DNS queries do not prove successful delivery.
                # Keep their exact labels unmapped; dnsteal.domain.match on the
                # same row independently supports the exfiltration attack type.
            },
            _parse_dns_line,
        ),
    },
}
for _scenario, _apache_log in _EXTENDED_APACHE_LOGS.items():
    _audit_pairs = {
        **_AUDIT_PAIRS,
        ("attacker_change_user", "attacker.escalate.audit.su.login"): "privilege_escalation",
    }
    if _scenario == "wilson":
        _audit_pairs[
            ("escalated_sudo_command", "attacker.escalate.audit.sudo.command.events_iptables")
        ] = "privilege_escalation"
    _dns_pairs = dict(_DNS_PAIRS)
    if _scenario == "harrison":
        _dns_pairs.update({
            ("dirb", "attacker_foothold_dnsmasq_dirb_parent_query"): "reconnaissance",
            ("dirb", "attacker_foothold_dnsmasq_dirb_sub_query"): "reconnaissance",
        })
    _SCENARIOS[f"ait-v2.1:{_scenario}"] = {
        _apache_log: (f"{_scenario}-apache-taxonomy-v1", dict(_PAIRS), _parser.parse_apache_line),
        _AUDIT_LOG: (f"{_scenario}-intranet-audit-taxonomy-v1", _audit_pairs, _audit_parser.parse_audit_line),
        _DNS_LOG: (f"{_scenario}-dnsmasq-taxonomy-v1", _dns_pairs, _parse_dns_line),
    }


def _profile(log, dataset_id=_DATASET):
    if not isinstance(dataset_id, str) or dataset_id not in _SCENARIOS:
        raise ValueError("unsupported taxonomy dataset_id")
    if not isinstance(log, str) or log not in _SCENARIOS[dataset_id]:
        raise ValueError("unsupported taxonomy source path for dataset_id")
    return _SCENARIOS[dataset_id][log]


def _official_md5(dataset_id):
    # Preserve the historical Fox checksum patch seam used by synthetic tests.
    if dataset_id == _DATASET:
        return _OFFICIAL_MD5
    if dataset_id == _RUSSELL_DATASET:
        return _RUSSELL_OFFICIAL_MD5
    return _EXTENDED_OFFICIAL_MD5[dataset_id]


def _check_observation(event, parsed, *, exact_keys=False, description="event"):
    if (exact_keys and set(event) != set(parsed)) or any(
        key not in event or type(event[key]) is not type(value) or event[key] != value
        for key, value in parsed.items()
    ):
        raise ValueError(f"{description} observation differs from source")


_KEYS = (
    "dataset_id",
    "relative_log_path",
    "line_number",
    "external_id",
    "raw_line_sha256",
)


def _annotation(row):
    labels, rules = row.get("labels"), row.get("rules")
    if (
        not isinstance(labels, list)
        or any(not isinstance(x, str) or not x for x in labels)
        or not isinstance(rules, dict)
        or set(labels) != set(rules)
        or any(
            not isinstance(v, list) or any(not isinstance(x, str) or not x for x in v)
            for v in rules.values()
        )
    ):
        raise ValueError("invalid labels/rules")
    return labels, rules


def classify_record(record: dict, *, completeness_verified: bool = False) -> dict:
    """Retain annotations and map only reviewed exact label/rule pairs."""
    version, pairs, _ = _profile(
        record.get("relative_log_path", _LOG), record.get("dataset_id", _DATASET)
    )
    labels, rules = _annotation(record)
    evidence = []
    unmapped = []
    for label in labels:
        mapped = False
        for rule in rules[label]:
            attack_type = pairs.get((label, rule))
            if attack_type:
                evidence.append(
                    {"label": label, "rule": rule, "attack_type": attack_type}
                )
                mapped = True
        if not mapped:
            unmapped.append(label)
    normal = (
        completeness_verified
        and not labels
        and not rules
        and record.get("annotation_status") == "unlabeled_unknown"
    )
    return {
        **record,
        "is_attack": True if labels else False if normal else None,
        "attack_types": [
            t for t in ATTACK_TYPES if any(e["attack_type"] == t for e in evidence)
        ],
        "mapping_evidence": evidence,
        "unmapped_labels": unmapped,
        "taxonomy_version": version,
        "normal_basis": _POLICY if normal else None,
    }


def _hash(path, algorithm="sha256"):
    digest = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _paths(paths):
    result = {}
    for name, value in paths.items():
        path = Path(value)
        _parser._reject_path_links(path)
        path = path.resolve()
        if not path.is_file():
            raise FileNotFoundError(path)
        result[name] = path
    return result


def _outputs(outputs, inputs, root, agent):
    resolved = []
    for value in outputs:
        path = Path(value)
        _parser._reject_path_links(path)
        path = path.resolve()
        if path in inputs or path.is_relative_to(root) or path.is_relative_to(agent):
            raise ValueError(
                "outputs must be outside raw/Agent inputs and distinct from inputs"
            )
        if path.exists():
            raise FileExistsError(path)
        if path in resolved:
            raise ValueError("outputs must be distinct")
        resolved.append(path)
    return resolved


def _bounds(start, end):
    start = _parser._utc_time(
        datetime.fromisoformat(start) if isinstance(start, str) else start
    )
    end = _parser._utc_time(
        datetime.fromisoformat(end) if isinstance(end, str) else end
    )
    if start >= end:
        raise ValueError("time_from must precede time_to")
    return start, end


def _scope(row, number, log=_LOG, dataset_id=_DATASET):
    if (
        row.get("dataset_id") != dataset_id
        or row.get("relative_log_path") != log
        or type(row.get("line_number")) is not int
        or row["line_number"] != number
    ):
        raise ValueError("invalid source key or incomplete physical line coverage")
    key = json.dumps([dataset_id, log, number], separators=(",", ":")).encode()
    if row.get("external_id") != "ait:" + hashlib.sha256(key).hexdigest():
        raise ValueError("invalid stable external_id")
    if not isinstance(row.get("raw_line_sha256"), str) or not re.fullmatch(
        "[0-9a-f]{64}", row["raw_line_sha256"]
    ):
        raise ValueError("invalid raw line hash")


def _archive_check(paths, log=_LOG, dataset_id=_DATASET, *, check_md5=True):
    if check_md5 and _hash(paths["archive"], "md5") != _official_md5(dataset_id):
        raise ValueError("official scenario archive MD5 mismatch")
    with zipfile.ZipFile(paths["archive"]) as archive:
        for name, kind in (("raw", "gather"), ("labels", "labels")):
            suffix = kind + "/" + log
            members = [
                x
                for x in archive.infolist()
                if x.filename == suffix or x.filename.endswith("/" + suffix)
            ]
            if len(members) != 1 or members[0].is_dir():
                raise ValueError("archive member missing or ambiguous")
            digest = hashlib.sha256()
            with archive.open(members[0]) as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            if digest.hexdigest() != _hash(paths[name]):
                raise ValueError("archive member differs from current input")


def verify(
    *, dataset_root, events, gold, join_report, archive, time_from, time_to, output
):
    """Stream and reparse every physical line; bind all six current input files."""
    _parser._reject_path_links(Path(dataset_root))
    root = Path(dataset_root).resolve()
    report_path = _paths({"join_report": join_report})["join_report"]
    report = _object(report_path.read_bytes())
    dataset_id = report.get("dataset_id")
    log = report.get("relative_log_path")
    version, _, parse_line = _profile(log, dataset_id)
    paths = _paths(
        {
            "raw": root / "gather" / log,
            "labels": root / "labels" / log,
            "events": events,
            "gold": gold,
            "join_report": report_path,
            "archive": archive,
        }
    )
    (destination,) = _outputs([output], paths.values(), root, paths["events"].parent)
    start, end = _bounds(time_from, time_to)
    for key, expected in {
        "truncated": False,
        "labels_complete_read": True,
        "label_bounds_verified": True,
        "labels_hash_scope": "complete",
        "unmatched_annotation_lines": 0,
    }.items():
        if type(report.get(key)) is not type(expected) or report[key] != expected:
            raise ValueError("join report is incomplete")
    _archive_check(paths, log, dataset_id)
    initial = {k: _hash(v) for k, v in paths.items()}
    counts = {
        "read_events": 0,
        "labeled_events": 0,
        "unlabeled_unknown_events": 0,
        "matched_annotation_lines": 0,
        "unmatched_annotation_lines": 0,
        "read_annotation_lines": 0,
        "raw_line_count": 0,
        "parse_errors": 0,
    }
    observed_min = observed_max = None
    previous_label = 0
    with (
        paths["raw"].open("rb") as source,
        paths["events"].open("rb") as event_stream,
        paths["gold"].open("rb") as gold_stream,
        paths["labels"].open("rb") as label_stream,
    ):

        def next_label():
            nonlocal previous_label
            raw = label_stream.readline()
            if not raw:
                return None
            row = _object(raw)
            previous_label = _join._number(row.get("line"), previous_label)
            _annotation(row)
            counts["read_annotation_lines"] += 1
            return row

        pending = next_label()
        for number, raw in enumerate(source, 1):
            event, record = (
                _object(event_stream.readline()),
                _object(gold_stream.readline()),
            )
            _scope(event, number, log, dataset_id)
            _scope(record, number, log, dataset_id)
            parsed = parse_line(
                raw.decode("utf-8"),
                dataset_id=dataset_id,
                relative_log_path=log,
                line_number=number,
                raw_line_sha256=hashlib.sha256(raw).hexdigest(),
            )
            if any(
                event.get(k) != parsed[k] or record.get(k) != parsed[k] for k in _KEYS
            ):
                raise ValueError("event/gold/raw source mismatch")
            if (
                event.get("observed_at") != parsed["observed_at"]
                or event.get("timestamp") != parsed["timestamp"]
            ):
                raise ValueError("event timestamp differs from actual source timestamp")
            if log == _DNS_LOG or dataset_id != _DATASET:
                _check_observation(
                    event,
                    parsed,
                    exact_keys=dataset_id != _DATASET,
                    description="DNS event/gold" if log == _DNS_LOG else "event",
                )
            if {
                "labels",
                "rules",
                "annotation_status",
                "is_attack",
                "attack_types",
                "dataset_labels",
                "mapping_evidence",
                "taxonomy_version",
                "normal_basis",
                "unmapped_labels",
            } & event.keys():
                raise ValueError("ground truth in Agent event")
            observed = datetime.fromisoformat(parsed["observed_at"])
            if not start <= observed < end:
                raise ValueError("event outside explicit time bounds")
            observed_min = (
                observed if observed_min is None else min(observed_min, observed)
            )
            observed_max = (
                observed if observed_max is None else max(observed_max, observed)
            )
            matched = pending is not None and pending["line"] == number
            expected_labels, expected_rules = (
                (pending["labels"], pending["rules"]) if matched else ([], {})
            )
            labels, rules = _annotation(record)
            status = "labeled" if labels else "unlabeled_unknown"
            if (
                labels != expected_labels
                or rules != expected_rules
                or record.get("annotation_status") != status
            ):
                raise ValueError("gold does not exactly match original annotation")
            counts["read_events"] += 1
            counts["raw_line_count"] += 1
            counts[status + "_events"] += 1
            if matched:
                counts["matched_annotation_lines"] += 1
                pending = next_label()
        if (
            pending is not None
            or event_stream.readline()
            or gold_stream.readline()
            or counts["read_events"] == 0
        ):
            raise ValueError("extra/missing lines or annotations outside source")
    for key, count in counts.items():
        if key != "parse_errors" and (
            type(report.get(key)) is not int or report[key] != count
        ):
            raise ValueError("join report count mismatch")
    if report.get("labels_sha256") != initial["labels"]:
        raise ValueError("join report labels hash mismatch")
    if any(_hash(path) != initial[name] for name, path in paths.items()):
        raise ValueError("input changed during verification")
    proof = {
        "schema_version": 1,
        "policy": _POLICY,
        "generator_version": version,
        "dataset_id": dataset_id,
        "relative_log_path": log,
        "verified": True,
        "time_from": start.isoformat(),
        "time_to": end.isoformat(),
        "observed_min": observed_min.isoformat(),
        "observed_max": observed_max.isoformat(),
        "generated_at": datetime.now(UTC).isoformat(),
        "counts": counts,
        "complete": True,
        "archive_md5": _official_md5(dataset_id),
        "dataset_root": str(root),
        "inputs": {k: {"path": str(v), "sha256": initial[k]} for k, v in paths.items()},
    }
    if log == _DNS_LOG:
        proof["timestamp_parameters"] = dict(_DNS_TIMESTAMP_PARAMETERS)
    destination.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with destination.open("x", encoding="utf-8") as stream:
            created = True
            stream.write(json.dumps(proof, indent=2) + "\n")
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise
    return proof


def _load_proof(path, gold):
    path = _paths({"proof": path})["proof"]
    proof = _object(path.read_bytes())
    dataset_id = proof.get("dataset_id")
    log = proof.get("relative_log_path")
    version, _, _ = _profile(log, dataset_id)
    for key, value in {
        "schema_version": 1,
        "policy": _POLICY,
        "generator_version": version,
        "dataset_id": dataset_id,
        "relative_log_path": log,
        "verified": True,
        "complete": True,
        "archive_md5": _official_md5(dataset_id),
    }.items():
        if type(proof.get(key)) is not type(value) or proof[key] != value:
            raise ValueError("invalid completeness proof")
    if log == _DNS_LOG:
        params = proof.get("timestamp_parameters")
        if (
            not isinstance(params, dict)
            or set(params) != set(_DNS_TIMESTAMP_PARAMETERS)
            or any(
                type(params[key]) is not type(value) or params[key] != value
                for key, value in _DNS_TIMESTAMP_PARAMETERS.items()
            )
        ):
            raise ValueError("invalid DNS timestamp parameters")
    try:
        start, end = _bounds(proof["time_from"], proof["time_to"])
        lower, upper = (
            _bounds(proof["observed_min"], proof["observed_max"])
            if proof["observed_min"] != proof["observed_max"]
            else (_parser._utc_time(datetime.fromisoformat(proof["observed_min"])),) * 2
        )
        _parser._utc_time(datetime.fromisoformat(proof["generated_at"]))
        if not start <= lower <= upper < end:
            raise ValueError("invalid observed bounds")
        inputs = proof["inputs"]
        if not isinstance(inputs, dict):
            raise TypeError("proof inputs must be an object")
        if set(inputs) != {"archive", "raw", "labels", "events", "gold", "join_report"}:
            raise ValueError("proof requires all six inputs")
        paths = _paths({k: v["path"] for k, v in inputs.items()})
        root = Path(proof["dataset_root"])
        _parser._reject_path_links(root)
        if not root.is_absolute() or root.resolve() != root:
            raise ValueError("dataset root must be canonical absolute path")
        if (
            paths["raw"] != root / "gather" / log
            or paths["labels"] != root / "labels" / log
            or paths["gold"] != Path(gold).resolve()
        ):
            raise ValueError("proof source paths mismatch")
        for name, current in paths.items():
            if (
                inputs[name]["path"] != str(current)
                or _hash(current) != inputs[name]["sha256"]
            ):
                raise ValueError("stale proof input hash")
        if _hash(paths["archive"], "md5") != _official_md5(dataset_id):
            raise ValueError("archive official MD5 mismatch")
        # A user-editable proof hash must not authorize a replacement raw log
        # or annotation sidecar. Rebind both to the already-checked archive.
        _archive_check(paths, log, dataset_id, check_md5=False)
        counts = proof["counts"]
        if not isinstance(counts, dict):
            raise TypeError("proof counts must be an object")
        required = {
            "read_events",
            "labeled_events",
            "unlabeled_unknown_events",
            "matched_annotation_lines",
            "unmatched_annotation_lines",
            "read_annotation_lines",
            "raw_line_count",
            "parse_errors",
        }
        if set(counts) != required or any(
            type(v) is not int or v < 0 for v in counts.values()
        ):
            raise ValueError("invalid proof counts")
        if (
            counts["read_events"] < 1
            or counts["read_events"] != counts["raw_line_count"]
            or counts["read_events"]
            != counts["labeled_events"] + counts["unlabeled_unknown_events"]
            or counts["parse_errors"] != 0
            or counts["unmatched_annotation_lines"] != 0
            or counts["matched_annotation_lines"] != counts["read_annotation_lines"]
            or not counts["labeled_events"]
            <= counts["matched_annotation_lines"]
            <= counts["read_events"]
        ):
            raise ValueError("contradictory proof counts")
        report = _object(paths["join_report"].read_bytes())
        if any(
            report.get(k) != counts[k] or type(report.get(k)) is not int
            for k in required - {"parse_errors"}
        ):
            raise ValueError("proof/report count mismatch")
        for key, value in {
            "dataset_id": dataset_id,
            "relative_log_path": log,
            "truncated": False,
            "labels_complete_read": True,
            "label_bounds_verified": True,
            "labels_hash_scope": "complete",
            "labels_sha256": inputs["labels"]["sha256"],
        }.items():
            if type(report.get(key)) is not type(value) or report[key] != value:
                raise ValueError("proof/report completeness mismatch")
    except (KeyError, TypeError) as exc:
        raise ValueError("malformed completeness proof") from exc
    return proof, paths, path


def map_gold(*, gold, proof, output, report, max_events=None):
    """Validate current content binding and write isolated scoring JSONL."""
    if max_events is not None and (type(max_events) is not int or max_events < 1):
        raise ValueError("max_events must be positive integer")
    bound, paths, proof_path = _load_proof(proof, gold)
    log = bound["relative_log_path"]
    dataset_id = bound["dataset_id"]
    _, _, parse_line = _profile(log, dataset_id)
    output, report = _outputs(
        [output, report],
        [*paths.values(), proof_path],
        Path(bound["dataset_root"]),
        paths["events"].parent,
    )
    summary = {
        "read_events": 0,
        "attack_events": 0,
        "normal_events": 0,
        "unknown_events": 0,
        "unmapped_attack_events": 0,
        "type_event_counts": dict.fromkeys(ATTACK_TYPES, 0),
        "truncated": False,
    }
    created = []
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        report.parent.mkdir(parents=True, exist_ok=True)
        with (
            paths["gold"].open("rb") as source,
            paths["raw"].open("rb") as raw_source,
            paths["labels"].open("rb") as annotations,
            paths["events"].open("rb") as events,
            output.open("x", encoding="utf-8", newline="\n") as destination,
        ):
            created.append(output)
            previous_label = 0
            read_annotations = 0

            def next_label():
                nonlocal previous_label, read_annotations
                raw = annotations.readline()
                if not raw:
                    return None
                row = _object(raw)
                previous_label = _join._number(row.get("line"), previous_label)
                _annotation(row)
                read_annotations += 1
                return row

            pending = next_label()
            for number, raw in enumerate(source, 1):
                if max_events is not None and number > max_events:
                    summary["truncated"] = True
                    break
                record = _object(raw)
                _scope(record, number, log, dataset_id)
                physical_line = raw_source.readline()
                if (
                    not physical_line
                    or record["raw_line_sha256"]
                    != hashlib.sha256(physical_line).hexdigest()
                ):
                    raise ValueError("gold/raw source mismatch")
                if dataset_id != _DATASET:
                    # Proof hashes are editable: reparse the official-bound raw
                    # line before accepting the current Agent event payload.
                    parsed = parse_line(
                        physical_line.decode("utf-8"),
                        dataset_id=dataset_id,
                        relative_log_path=log,
                        line_number=number,
                        raw_line_sha256=record["raw_line_sha256"],
                    )
                    _check_observation(
                        _object(events.readline()), parsed, exact_keys=True
                    )
                matched = pending is not None and pending["line"] == number
                expected_labels, expected_rules = (
                    (pending["labels"], pending["rules"]) if matched else ([], {})
                )
                labels, rules = _annotation(record)
                if labels != expected_labels or rules != expected_rules:
                    raise ValueError("gold does not exactly match original annotation")
                if record.get("annotation_status") != (
                    "labeled" if labels else "unlabeled_unknown"
                ):
                    raise ValueError("gold annotation status mismatch")
                mapped = classify_record(record, completeness_verified=True)
                summary["read_events"] += 1
                summary[
                    "attack_events" if mapped["is_attack"] else "normal_events"
                ] += 1
                summary["unmapped_attack_events"] += bool(
                    mapped["is_attack"] and not mapped["attack_types"]
                )
                for attack_type in mapped["attack_types"]:
                    summary["type_event_counts"][attack_type] += 1
                destination.write(json.dumps(mapped, ensure_ascii=False) + "\n")
                if matched:
                    pending = next_label()
            if not summary["truncated"] and (
                pending is not None
                or raw_source.readline()
                or read_annotations != bound["counts"]["read_annotation_lines"]
                or (dataset_id != _DATASET and events.readline())
            ):
                raise ValueError("extra/missing lines or annotations outside source")
        if not summary["truncated"] and (
            summary["read_events"] != bound["counts"]["read_events"]
            or summary["attack_events"] != bound["counts"]["labeled_events"]
            or summary["normal_events"] != bound["counts"]["unlabeled_unknown_events"]
        ):
            raise ValueError("full map counts differ from proof")
        if any(_hash(p) != bound["inputs"][k]["sha256"] for k, p in paths.items()):
            raise ValueError("input changed during mapping")
        with report.open("x", encoding="utf-8") as stream:
            created.append(report)
            stream.write(json.dumps(summary, indent=2) + "\n")
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return summary


def main(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    commands = cli.add_subparsers(dest="command", required=True)
    verify_cli = commands.add_parser("verify")
    for flag in ("dataset-root", "events", "gold", "join-report", "archive", "output"):
        verify_cli.add_argument("--" + flag, type=Path, required=True)
    for flag in ("time-from", "time-to"):
        verify_cli.add_argument("--" + flag, required=True)
    map_cli = commands.add_parser("map")
    for flag in ("gold", "proof", "output", "report"):
        map_cli.add_argument("--" + flag, type=Path, required=True)
    map_cli.add_argument("--max-events", type=int)
    args = vars(cli.parse_args(argv))
    command = args.pop("command")
    try:
        result = verify(**args) if command == "verify" else map_gold(**args)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        cli.error(str(exc))
    print(json.dumps(result["counts"] if command == "verify" else result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
