"""Build an isolated, time-selected AIT development case."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import stat
from contextlib import nullcontext
from datetime import UTC, datetime
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "_ait_case_taxonomy", Path(__file__).with_name("taxonomy.py")
)
assert _spec and _spec.loader
_taxonomy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_taxonomy)
_parser = _taxonomy._parser
_object = _taxonomy._object
_DATASET = "ait-v2.1:fox"
_PROFILES = {
    "intranet_server/logs/apache2/intranet.price.fox.org-access.log.2": "apache",
    "intranet_server/logs/audit/audit.log": "audit",
    "inet-firewall/logs/dnsmasq.log": "dnsmasq",
}
_APACHE_LOG = "intranet_server/logs/apache2/intranet.price.fox.org-access.log.2"
_DNS_LOG = "inet-firewall/logs/dnsmasq.log"
_RUSSELL_DATASET = "ait-v2.1:russellmitchell"
_RUSSELL_APACHE_LOG = (
    "intranet_server/logs/apache2/intranet.smith.russellmitchell.com-access.log.2"
)
_SCENARIOS = {
    _DATASET: {
        "scenario": "fox",
        "profiles": _PROFILES,
        "apache_log": _APACHE_LOG,
    },
    _RUSSELL_DATASET: {
        "scenario": "russellmitchell",
        "profiles": {
            _RUSSELL_APACHE_LOG: "apache",
            "intranet_server/logs/audit/audit.log": "audit",
            _DNS_LOG: "dnsmasq",
        },
        "apache_log": _RUSSELL_APACHE_LOG,
    },
}
for _scenario, _apache_log in _taxonomy._EXTENDED_APACHE_LOGS.items():
    _SCENARIOS[f"ait-v2.1:{_scenario}"] = {
        "scenario": _scenario,
        "profiles": {
            _apache_log: "apache",
            "intranet_server/logs/audit/audit.log": "audit",
            _DNS_LOG: "dnsmasq",
        },
        "apache_log": _apache_log,
    }
_FORBIDDEN = {
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
_SPLITS = {
    "development": ["fox", "harrison", "russellmitchell", "santos", "wheeler"],
    "validation": ["wardbeck"],
    "test": ["shaw", "wilson"],
}


def _hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _strict_json(path):
    # Windows-created JSON metadata may have a UTF-8 BOM; hashes still bind
    # the original file bytes, and streamed event/gold JSONL stays strict.
    return _object(Path(path).read_bytes().removeprefix(b"\xef\xbb\xbf"))


def _canonical(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _same(left, right):
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _same(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _same(a, b) for a, b in zip(left, right, strict=True)
        )
    return left == right


def _time(value):
    if not isinstance(value, str):
        raise TypeError("time bounds must be timezone-aware strings")
    return _parser._utc_time(datetime.fromisoformat(value.replace("Z", "+00:00")))


def _snapshot(initial, path, digest=None):
    _parser._reject_path_links(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    digest = _hash(path) if digest is None else digest
    key = str(path)
    if key in initial and initial[key] != digest:
        raise ValueError("input changed during loading")
    initial[key] = digest


def _check_snapshot(initial):
    for name, digest in initial.items():
        path = Path(name)
        _parser._reject_path_links(path)
        if _hash(path) != digest:
            raise ValueError("input changed during build")


def _safe_inputs(config_path, initial, *, data_root=None):
    config_path = Path(config_path).absolute()
    _parser._reject_path_links(config_path)
    config_path = config_path.resolve()
    config = _strict_json(config_path)
    expected = {"schema_version", "dataset_id", "scenario", "split", "sources"}
    if not isinstance(config, dict):
        raise TypeError("invalid source configuration")
    schema_version = config.get("schema_version")
    dataset_id = config.get("dataset_id")
    split = config.get("split")
    reviewed = _SCENARIOS.get(dataset_id) if isinstance(dataset_id, str) else None
    if (
        set(config) != expected
        or type(schema_version) is not int
        or schema_version not in (1, 2)
        or reviewed is None
        or not isinstance(split, str)
        or split not in _SPLITS
        or (schema_version == 1 and (dataset_id != _DATASET or split != "development"))
        or any(
            type(config.get(k)) is not type(v) or config[k] != v
            for k, v in {
                "dataset_id": dataset_id,
                "scenario": reviewed["scenario"] if reviewed else None,
                "split": split,
            }.items()
        )
        or reviewed["scenario"] not in _SPLITS[split]
    ):
        raise ValueError("invalid source configuration")
    rows = config["sources"]
    profiles = reviewed["profiles"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= len(profiles):
        raise ValueError("one to three reviewed profiles are required")
    if schema_version == 1 and len(rows) != 3:
        raise ValueError("exactly three Fox profiles are required")
    resolved, seen = [], set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "relative_log_path",
            "events",
            "scored_gold",
            "proof",
        }:
            raise ValueError("invalid source entry")
        log = row["relative_log_path"]
        if (
            not isinstance(log, str)
            or log not in profiles
            or log in seen
            or any(
                not isinstance(row[k], str) or not row[k]
                for k in ("events", "scored_gold", "proof")
            )
        ):
            raise ValueError("source profile mismatch or duplicate")
        seen.add(log)
        paths = {}
        for key in ("events", "scored_gold", "proof"):
            candidate = Path(row[key])
            if candidate.is_absolute():
                raise ValueError("configured input paths must be relative")
            if not candidate.is_absolute():
                candidate = config_path.parent / candidate
            _parser._reject_path_links(candidate)
            paths[key] = candidate.resolve()
            if data_root is not None:
                _taxonomy._relative_reference(paths[key], data_root)
        for path in paths.values():
            if not path.is_file():
                raise FileNotFoundError(path)
        proof_raw = paths["proof"].read_bytes()
        _snapshot(initial, paths["proof"], hashlib.sha256(proof_raw).hexdigest())
        captured = _object(proof_raw)
        if not isinstance(captured, dict) or captured.get("dataset_id") != dataset_id:
            raise ValueError("proof dataset differs from source")
        try:
            captured_inputs = captured["inputs"]
            if set(captured_inputs) != {
                "archive",
                "raw",
                "labels",
                "events",
                "gold",
                "join_report",
            }:
                raise ValueError("proof requires all six inputs")
            captured_paths = _taxonomy._paths(
                {key: value["path"] for key, value in captured_inputs.items()},
                data_root=data_root if captured.get("schema_version") == 2 else None,
            )
            if data_root is not None and captured.get("schema_version") != 2:
                raise ValueError(
                    "explicit data root requires a portable completeness proof"
                )
            gold = captured_paths["gold"]
            for path in [*captured_paths.values(), *paths.values()]:
                _snapshot(initial, path)
            if any(
                initial[str(path)] != captured_inputs[key]["sha256"]
                for key, path in captured_paths.items()
            ):
                raise ValueError("stale proof input hash")
        except (KeyError, TypeError) as exc:
            raise ValueError("malformed completeness proof") from exc
        proof, proof_inputs, proof_path = _taxonomy._load_proof(
            paths["proof"],
            gold,
            **({"data_root": data_root} if data_root is not None else {}),
        )
        if (
            not _same(proof, captured)
            or proof_inputs != captured_paths
            or proof_path != paths["proof"]
        ):
            raise ValueError("completeness proof changed during loading")
        _check_snapshot(initial)
        if proof["relative_log_path"] != log:
            raise ValueError("proof profile differs from source")
        if proof["dataset_id"] != dataset_id:
            raise ValueError("proof dataset differs from source")
        expected_paths = {
            "events": proof_inputs["events"],
            "scored_gold": paths["scored_gold"],
        }
        if expected_paths["events"] != paths["events"]:
            raise ValueError("Agent events path differs from proof")
        resolved.append((log, paths, proof, proof_inputs, proof_path))
    if schema_version == 1 and seen != set(profiles):
        raise ValueError("all Fox profiles are required")
    return config_path, config, resolved


def _check_splits(path):
    path = Path(path).absolute()
    _parser._reject_path_links(path)
    path = path.resolve()
    value = _strict_json(path)
    if set(value) != set(_SPLITS):
        raise ValueError("split file must contain exactly three splits")
    for key, expected in _SPLITS.items():
        rows = value[key]
        if (
            not isinstance(rows, list)
            or not rows
            or any(not isinstance(x, str) or not x for x in rows)
            or len(rows) != len(set(rows))
            or rows != expected
        ):
            raise ValueError("split configuration differs from reviewed AIT splits")
    return path, value


def _contains_gold(value):
    if isinstance(value, dict):
        return any(k in _FORBIDDEN or _contains_gold(v) for k, v in value.items())
    if isinstance(value, list):
        return any(_contains_gold(v) for v in value)
    return False


def build_case(
    *,
    source_config,
    splits,
    case_id,
    time_from,
    time_to,
    output_dir,
    max_records=10000,
    data_root=None,
):
    return _build_case(
        source_config=source_config,
        splits=splits,
        case_id=case_id,
        time_from=time_from,
        time_to=time_to,
        output_dir=output_dir,
        max_records=max_records,
        data_root=data_root,
    )


def _owned_identity(metadata):
    return metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)


def _cleanup_owned(created, *, directories=False):
    for path, identity in reversed(created):
        try:
            _parser._reject_path_links(path)
            if _owned_identity(path.lstat()) == identity:
                path.rmdir() if directories else path.unlink()
        except (OSError, ValueError):
            # A concurrent object or a nonempty directory belongs to its owner.
            pass


def _mkdir_owned(path, created):
    _parser._reject_path_links(path)
    path.mkdir()
    created.append((path, _owned_identity(path.lstat())))


def _neutral_case_id(config, start, end, max_records):
    # Gold paths, annotations, chosen labels and legacy IDs are deliberately absent.
    identity = {
        "dataset_id": config["dataset_id"],
        "scenario": config["scenario"],
        "split": config["split"],
        "time_from": start.isoformat(),
        "time_to": end.isoformat(),
        "sources": sorted(row["relative_log_path"] for row in config["sources"]),
        "max_records": max_records,
    }
    return "ait-" + hashlib.sha256(_canonical(identity).encode()).hexdigest()[:24]


def neutral_case_id(*, source_config, time_from, time_to, max_records=10000):
    config = json.loads(Path(source_config).read_text(encoding="utf-8-sig"))
    return _neutral_case_id(config, _time(time_from), _time(time_to), max_records)


def case_data_root(*, source_config, data_root, explicit=False):
    """Retain legacy defaults while automatically recognizing portable proofs."""
    if explicit:
        return data_root
    path = Path(source_config)
    config = json.loads(path.read_text(encoding="utf-8-sig"))
    for row in config["sources"]:
        proof = json.loads((path.parent / row["proof"]).read_text(encoding="utf-8-sig"))
        if proof.get("schema_version") == 2:
            return data_root
    return None


def _build_case(
    *,
    source_config,
    splits,
    case_id,
    time_from,
    time_to,
    output_dir,
    max_records=10000,
    expected_manifest=None,
    manifest_snapshot=None,
    data_root=None,
):
    if not isinstance(case_id, str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9_-]{0,63}", case_id
    ):
        raise ValueError("invalid neutral case_id")
    if type(max_records) is not int or max_records < 1:
        raise ValueError("max_records must be a positive integer")
    start, end = _time(time_from), _time(time_to)
    if start >= end:
        raise ValueError("time_from must precede time_to")
    config_lexical = Path(source_config).absolute()
    _parser._reject_path_links(config_lexical)
    config_hash_at_start = _hash(config_lexical)
    initial = {str(config_lexical.resolve()): config_hash_at_start}
    if data_root is not None:
        data_root = _taxonomy._data_root(data_root)
        _taxonomy._relative_reference(config_lexical, data_root)
    config_path, _config, sources = _safe_inputs(
        config_lexical, initial, data_root=data_root
    )
    schema_version = _config["schema_version"]
    dataset_id = _config["dataset_id"]
    scenario = _config["scenario"]
    split = _config["split"]
    if data_root is not None and case_id != _neutral_case_id(
        _config, start, end, max_records
    ):
        raise ValueError("portable packs require the neutral case identity")
    apache_log = _SCENARIOS[dataset_id]["apache_log"]
    splits_lexical = Path(splits).absolute()
    _parser._reject_path_links(splits_lexical)
    splits_hash_at_start = _hash(splits_lexical)
    _snapshot(initial, splits_lexical.resolve(), splits_hash_at_start)
    splits_path, _split_data = _check_splits(splits_lexical)
    if data_root is not None:
        _taxonomy._relative_reference(splits_path, data_root)
    _check_snapshot(initial)
    all_paths = [path for _, paths, _, _, _ in sources for path in paths.values()]
    if len(all_paths) != len(set(all_paths)):
        raise ValueError("source input files cannot be reused across profiles")
    dest = Path(output_dir).absolute()
    _parser._reject_path_links(dest)
    dest = dest.resolve()
    if data_root is not None and dest.name != case_id:
        raise ValueError("portable case folder must equal the neutral case identity")
    protected = [
        p
        for _, paths, _, proof_inputs, proof_path in sources
        for p in [*paths.values(), proof_path, *proof_inputs.values()]
    ]
    protected.extend((config_path, splits_path))
    if manifest_snapshot is not None:
        protected.extend(Path(path) for path in manifest_snapshot)
    protected_roots = [
        config_path.parent,
        splits_path.parent,
        *(Path(path).parent for path in (manifest_snapshot or {})),
        *(
            _taxonomy._resolve_reference(proof["dataset_root"], data_root)
            if proof["schema_version"] == 2
            else Path(proof["dataset_root"])
            for _, _, proof, _, _ in sources
        ),
        *(paths["events"].parent for _, paths, _, _, _ in sources),
        *(
            path.parent
            for _, paths, _, proof_inputs, proof_path in sources
            for path in [*paths.values(), proof_path, *proof_inputs.values()]
        ),
    ]
    if any(
        dest == p or dest.is_relative_to(p) or p.is_relative_to(dest) for p in protected
    ) or any(dest == root or dest.is_relative_to(root) for root in protected_roots):
        raise ValueError("output overlaps protected input")
    created = []
    created_dirs = []
    try:
        missing = [dest]
        parent = dest.parent
        while not parent.exists():
            missing.append(parent)
            parent = parent.parent
        for directory in reversed(missing):
            _mkdir_owned(directory, created_dirs)
        for subdir in (dest / "agent", dest / "scoring"):
            _mkdir_owned(subdir, created_dirs)
        chosen, stats = (
            [],
            {
                "attack": 0,
                "normal": 0,
                "unknown": 0,
                "unmapped": 0,
                "types": {t: 0 for t in _taxonomy.ATTACK_TYPES},
            },
        )
        for log, paths, proof, proof_inputs, proof_path in sources:
            proof_start, proof_end = _time(proof["time_from"]), _time(proof["time_to"])
            if start < proof_start or end > proof_end:
                raise ValueError("requested window exceeds a complete source proof")
            event_path, scored_path = paths["events"], paths["scored_gold"]
            original_path = proof_inputs["gold"]
            verify_raw = dataset_id != _DATASET
            parse_line = _taxonomy._profile(log, dataset_id)[2] if verify_raw else None
            n = 0
            with (
                event_path.open("rb") as ef,
                scored_path.open("rb") as sf,
                original_path.open("rb") as of,
                (
                    proof_inputs["raw"].open("rb") if verify_raw else nullcontext()
                ) as raw_stream,
            ):
                for n, (eraw, sraw, oraw) in enumerate(zip(ef, sf, of, strict=True), 1):
                    event, row, original = _object(eraw), _object(sraw), _object(oraw)
                    _taxonomy._scope(event, n, log, dataset_id)
                    _taxonomy._scope(row, n, log, dataset_id)
                    _taxonomy._scope(original, n, log, dataset_id)
                    if verify_raw:
                        raw = raw_stream.readline()
                        if not raw:
                            raise ValueError("Agent event differs from raw source")
                        parsed = parse_line(
                            raw.decode("utf-8"),
                            dataset_id=dataset_id,
                            relative_log_path=log,
                            line_number=n,
                            raw_line_sha256=hashlib.sha256(raw).hexdigest(),
                        )
                        if not _same(event, parsed):
                            raise ValueError("Agent event differs from raw source")
                    source_keys = (
                        "dataset_id",
                        "relative_log_path",
                        "line_number",
                        "external_id",
                        "raw_line_sha256",
                    )
                    if any(
                        not _same(event.get(key), row.get(key))
                        or not _same(row.get(key), original.get(key))
                        for key in source_keys
                    ):
                        raise ValueError(
                            "source keys differ across event and gold files"
                        )
                    mapped = _taxonomy.classify_record(
                        original, completeness_verified=True
                    )
                    if not _same(mapped, row):
                        raise ValueError(
                            "scored gold differs from canonical complete mapping"
                        )
                    stamp = event.get("observed_at")
                    observed = (
                        datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                        if isinstance(stamp, str)
                        else None
                    )
                    if observed is None or observed.tzinfo is None:
                        raise ValueError(
                            "Agent timestamps must be matching and timezone-aware"
                        )
                    observed = observed.astimezone(UTC)
                    timestamp = datetime.fromisoformat(
                        event["timestamp"].replace("Z", "+00:00")
                    )
                    if (
                        timestamp.tzinfo is None
                        or timestamp.astimezone(UTC) != observed
                    ):
                        raise ValueError("Agent timestamps differ as UTC instants")
                    if not (
                        _time(proof["observed_min"])
                        <= observed
                        <= _time(proof["observed_max"])
                    ):
                        raise ValueError("Agent timestamp falls outside proof range")
                    if _contains_gold(event):
                        raise ValueError("Agent event contains structured gold fields")
                    if start <= observed < end:
                        chosen.append((observed, log, n, event, row))
                        if len(chosen) > max_records:
                            raise ValueError("selected record limit exceeded")
                if verify_raw and raw_stream.readline():
                    raise ValueError("Agent event differs from raw source")
            if n != proof["counts"]["read_events"]:
                raise ValueError("input row count differs from complete proof")
        chosen.sort(key=lambda item: (item[0], item[1], item[2]))
        if not chosen:
            raise ValueError("time window selected no records")
        per_source = {
            log: {"selected": 0, "attack": 0, "normal": 0, "unknown": 0}
            for log, _, _, _, _ in sources
        }
        for _, log, _, event, row in chosen:
            state = (
                "attack"
                if row["is_attack"] is True
                else "normal"
                if row["is_attack"] is False
                else "unknown"
            )
            stats[state] += 1
            per_source[log]["selected"] += 1
            per_source[log][state] += 1
            stats["unmapped"] += bool(
                row["is_attack"] is True and not row["attack_types"]
            )
            for kind in row["attack_types"]:
                stats["types"][kind] += 1
        ids_by_ip, candidates, attack_times = {}, [], []
        for _, log, _, event, row in chosen:
            if row["is_attack"] is not True:
                continue
            observed_attack = datetime.fromisoformat(
                event["observed_at"].replace("Z", "+00:00")
            ).astimezone(UTC)
            attack_times.append((observed_attack, event["external_id"]))
            source_ip = event.get("source_ip")
            role = (
                "http_client"
                if log == apache_log
                else "dns_query_client"
                if log == _DNS_LOG
                else None
            )
            if role == "dns_query_client" and event.get("dns_record_kind") != "query":
                role = None
            if role and source_ip:
                value = str(ipaddress.ip_address(source_ip))
                ids_by_ip.setdefault((role, value), []).append(event["external_id"])
            if (
                log == apache_log
                and event.get("host")
                and all(
                    event.get(k)
                    for k in ("http_method", "request_target", "http_version")
                )
            ):
                key = (event["host"], "apache_http")
                candidate = next(
                    (c for c in candidates if (c["host"], c["service"]) == key), None
                )
                if candidate is None:
                    candidate = {
                        "host": event["host"],
                        "service": "apache_http",
                        "status": "observed_http_endpoint_candidate",
                        "evidence_ids": [],
                    }
                    candidates.append(candidate)
                candidate["evidence_ids"].append(event["external_id"])
        first = min((x[0] for x in attack_times), default=None)
        source_gold = {
            "scope": "selected_window",
            "basis": "observed_log_fields_plus_verified_annotations",
            "observed_source_ips": [
                {"value": ip, "role": role, "evidence_ids": sorted(set(ids))}
                for (role, ip), ids in sorted(ids_by_ip.items())
            ],
            "entry_candidates": candidates,
            "first_attack_time": {
                "status": "observed_in_selected_window" if first else "not_observed",
                "value": first.isoformat() if first else None,
                "evidence_ids": sorted(i for t, i in attack_times if t == first)
                if first
                else [],
            },
            "subsequent_hosts": {
                "status": "not_observed",
                "values": [],
                "evidence_ids": [],
            },
            "external_attacker_identity": {
                "status": "not_established",
                "dns_query_client_semantics": "A DNS query source is the observed local query client; it does not establish an external attacker.",
            },
        }
        agent_data = b"".join(
            (
                json.dumps(r[3], ensure_ascii=False, separators=(",", ":")) + "\n"
            ).encode()
            for r in chosen
        )
        gold_data = b"".join(
            (
                json.dumps(r[4], ensure_ascii=False, separators=(",", ":")) + "\n"
            ).encode()
            for r in chosen
        )

        def emit(relative, data):
            path = dest / relative
            _parser._reject_path_links(path)
            with path.open("xb") as stream:
                created.append((path, _owned_identity(os.fstat(stream.fileno()))))
                stream.write(data)

        emit("agent/events.jsonl", agent_data)
        agent_manifest = {
            "schema_version": schema_version,
            "generator_version": f"ait-{scenario}-agent-case-v{schema_version}",
            "case_id": case_id,
            "dataset_id": dataset_id,
            "scenario": scenario,
            "split": split,
            "time_from": start.isoformat(),
            "time_to": end.isoformat(),
            "selection": "observed_at in [time_from,time_to), independent of labels",
            "event_count": len(chosen),
            "events_file": "events.jsonl",
            "events_sha256": hashlib.sha256(agent_data).hexdigest(),
            "sources": sorted({r[1] for r in chosen}),
        }
        emit("agent/manifest.json", (_canonical(agent_manifest) + "\n").encode())
        emit("scoring/gold.jsonl", gold_data)
        emit("scoring/source-gold.json", (_canonical(source_gold) + "\n").encode())

        def reference(path):
            return (
                _taxonomy._relative_reference(path, data_root)
                if data_root is not None
                else str(path)
            )

        ledger = dict(sorted((reference(k), v) for k, v in initial.items()))
        scoring = {
            "schema_version": schema_version,
            "case_id": case_id,
            "dataset_id": dataset_id,
            "scenario": scenario,
            "split": split,
            "generator_version": f"ait-{scenario}-{split}-case-v{schema_version}",
            "build": {
                "source_config": reference(config_path),
                "source_config_sha256": initial[str(config_path)],
                "splits": reference(splits_path),
                "splits_sha256": initial[str(splits_path)],
                "case_id": case_id,
                "time_from": start.isoformat(),
                "time_to": end.isoformat(),
                "max_records": max_records,
                **({"path_base": "data_root"} if data_root is not None else {}),
            },
            "input_sha256": ledger,
            "profiles": [
                {"relative_log_path": l, "taxonomy_version": p["generator_version"]}
                for l, _, p, _, _ in sorted(sources, key=lambda item: item[0])
            ],
            "counts": {**stats, "selected": len(chosen), "per_source": per_source},
            "artifacts": {
                "agent/events.jsonl": hashlib.sha256(agent_data).hexdigest(),
                "agent/manifest.json": _hash(dest / "agent/manifest.json"),
                "scoring/gold.jsonl": hashlib.sha256(gold_data).hexdigest(),
                "scoring/source-gold.json": _hash(dest / "scoring/source-gold.json"),
            },
            "artifact_records": {
                "agent/events.jsonl": len(chosen),
                "scoring/gold.jsonl": len(chosen),
            },
        }
        emit("scoring/manifest.json", (_canonical(scoring) + "\n").encode())
        if expected_manifest is not None and not _same(scoring, expected_manifest):
            raise ValueError("rebuild differs from trusted scoring manifest")
        _check_snapshot(initial)
        if manifest_snapshot is not None:
            _check_snapshot(manifest_snapshot)
        return {
            "case_id": case_id,
            "event_count": len(chosen),
            "counts": scoring["counts"],
        }
    except BaseException:
        _cleanup_owned(created)
        _cleanup_owned(created_dirs, directories=True)
        raise


def rebuild_case(*, manifest, output_dir, data_root=None):
    manifest_path = Path(manifest).absolute()
    _parser._reject_path_links(manifest_path)
    manifest_path = manifest_path.resolve()
    if not manifest_path.is_file():
        raise FileNotFoundError(manifest_path)
    manifest_raw = manifest_path.read_bytes()
    manifest_snapshot = {str(manifest_path): hashlib.sha256(manifest_raw).hexdigest()}
    source = _object(manifest_raw.removeprefix(b"\xef\xbb\xbf"))
    if not isinstance(source, dict):
        raise TypeError("unsupported or malformed scoring manifest")
    dataset_id = source.get("dataset_id")
    split = source.get("split")
    reviewed = _SCENARIOS.get(dataset_id) if isinstance(dataset_id, str) else None
    supported_versions = (
        (1, 2) if dataset_id == _DATASET and split == "development" else (2,)
    )
    if (
        set(source)
        != {
            "schema_version",
            "case_id",
            "dataset_id",
            "scenario",
            "split",
            "generator_version",
            "build",
            "input_sha256",
            "profiles",
            "counts",
            "artifacts",
            "artifact_records",
        }
        or reviewed is None
        or not isinstance(split, str)
        or split not in _SPLITS
        or reviewed["scenario"] not in _SPLITS[split]
        or not any(
            _same(source.get("schema_version"), version)
            and _same(
                source.get("generator_version"),
                f"ait-{reviewed['scenario']}-{split}-case-v{version}",
            )
            for version in supported_versions
        )
        or any(
            not _same(source.get(key), value)
            for key, value in {
                "dataset_id": dataset_id,
                "scenario": reviewed["scenario"],
                "split": split,
            }.items()
        )
    ):
        raise ValueError("unsupported or malformed scoring manifest")
    build = source["build"]
    portable = isinstance(build, dict) and build.get("path_base") == "data_root"
    if not isinstance(build, dict) or set(build) != {
        "source_config",
        "source_config_sha256",
        "splits",
        "splits_sha256",
        "case_id",
        "time_from",
        "time_to",
        "max_records",
    } | ({"path_base"} if portable else set()):
        raise ValueError("malformed scoring manifest build")
    ledger = source["input_sha256"]
    if portable:
        data_root = _taxonomy._data_root(data_root)
        for reference in ledger:
            _taxonomy._resolve_reference(reference, data_root)
    if (
        not isinstance(ledger, dict)
        or not ledger
        or any(
            not isinstance(path, str)
            or not path
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            for path, digest in ledger.items()
        )
        or any(
            not isinstance(build[key], str) or not build[key]
            for key in build.keys() - {"max_records"}
        )
        or not _same(source["case_id"], build["case_id"])
        or ledger.get(build["source_config"]) != build["source_config_sha256"]
        or ledger.get(build["splits"]) != build["splits_sha256"]
    ):
        raise ValueError("malformed scoring manifest input ledger")
    return _build_case(
        source_config=_taxonomy._resolve_reference(build["source_config"], data_root)
        if portable
        else build["source_config"],
        splits=_taxonomy._resolve_reference(build["splits"], data_root)
        if portable
        else build["splits"],
        case_id=build["case_id"],
        time_from=build["time_from"],
        time_to=build["time_to"],
        output_dir=output_dir,
        max_records=build["max_records"],
        expected_manifest=source,
        manifest_snapshot=manifest_snapshot,
        data_root=data_root if portable else None,
    )


def main(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    commands = cli.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    for arg in (
        "source-config",
        "splits",
        "case-id",
        "time-from",
        "time-to",
        "output-dir",
    ):
        build.add_argument("--" + arg, required=True)
    build.add_argument("--max-records", type=int, default=10000)
    rebuild = commands.add_parser("rebuild")
    rebuild.add_argument("--manifest", required=True)
    rebuild.add_argument("--output-dir", required=True)
    build.add_argument("--data-root")
    rebuild.add_argument("--data-root")
    args = vars(cli.parse_args(argv))
    command = args.pop("command")
    result = (
        build_case(**{k.replace("-", "_"): v for k, v in args.items()})
        if command == "build"
        else rebuild_case(**args)
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
