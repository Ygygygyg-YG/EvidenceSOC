import hashlib
import importlib.util
import json
import os
import zipfile
from pathlib import Path

import pytest

BASE = Path(__file__).resolve().parents[1] / "datasets/ait_v2"
DATASET = "ait-v2.1:russellmitchell"
LOGS = (
    "intranet_server/logs/apache2/intranet.smith.russellmitchell.com-access.log.2",
    "intranet_server/logs/audit/audit.log",
    "inet-firewall/logs/dnsmasq.log",
)
ARTIFACTS = (
    "agent/events.jsonl",
    "agent/manifest.json",
    "scoring/gold.jsonl",
    "scoring/source-gold.json",
    "scoring/manifest.json",
)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def russell_sources(tmp_path, monkeypatch):
    taxonomy = load("russell_case_taxonomy", BASE / "taxonomy.py")
    builder = load("russell_case_builder", BASE / "build_manifests.py")
    audit = load("russell_case_audit", BASE / "audit_parse.py")
    dns = load("russell_case_dns", BASE / "dnsmasq_parse.py")
    root = tmp_path / "raw"
    archive = tmp_path / "archives" / "russell.zip"
    archive.parent.mkdir()
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    specs = (
        (
            b'192.0.2.8 - - [23/Jan/2022:12:00:01 +0000] "GET /x HTTP/1.1" 200 1 "-" "fixture"\n',
            "webshell_cmd",
            "attacker.escalate.webshell.cmd.http",
        ),
        (
            b"type=USER_CMD msg=audit(1642939202.000:42): fixture\n",
            "escalated_sudo_command",
            "attacker.escalate.audit.sudo.command.start",
        ),
        (
            b"Jan 23 12:00:03 dnsmasq[42]: query[A] example.test from 192.0.2.9\n",
            "dnsteal",
            "dnsteal.domain.match",
        ),
    )
    source_entries = []
    pending = []
    with zipfile.ZipFile(archive, "w") as bundle:
        for index, (raw, label, rule) in enumerate(specs):
            log = LOGS[index]
            raw_path = root / "gather" / log
            label_path = root / "labels" / log
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            label_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_bytes(raw)
            label_path.write_text(
                json.dumps({"line": 1, "labels": [label], "rules": {label: [rule]}})
                + "\n",
                encoding="utf-8",
            )
            bundle.write(raw_path, "russellmitchell/gather/" + log)
            bundle.write(label_path, "russellmitchell/labels/" + log)
            event = tmp_path / "events" / f"events-{index}.jsonl"
            event.parent.mkdir(exist_ok=True)
            errors = tmp_path / "errors" / f"errors-{index}.jsonl"
            errors.parent.mkdir(exist_ok=True)
            kwargs = {
                "dataset_root": root,
                "dataset_id": DATASET,
                "relative_log_path": log,
                "output": event,
                "errors": errors,
            }
            if index == 0:
                taxonomy._parser.parse_apache_file(**kwargs)
            elif index == 1:
                audit.parse_audit_file(**kwargs)
            else:
                dns.parse_dnsmasq_file(**kwargs, year=2022, utc_offset="+00:00")
            gold = tmp_path / "gold" / f"gold-{index}.jsonl"
            gold.parent.mkdir(exist_ok=True)
            join = tmp_path / "reports" / f"join-{index}.json"
            join.parent.mkdir(exist_ok=True)
            taxonomy._join.join_labels(
                dataset_root=root,
                dataset_id=DATASET,
                relative_log_path=log,
                events=event,
                output=gold,
                report=join,
            )
            scored = tmp_path / "scored" / f"scored-{index}.jsonl"
            scored.parent.mkdir(exist_ok=True)
            proof = tmp_path / "proofs" / f"proof-{index}.json"
            proof.parent.mkdir(exist_ok=True)
            map_report = tmp_path / "reports" / f"map-{index}.json"
            pending.append((event, gold, join, proof, scored, map_report))
            source_entries.append(
                {
                    "relative_log_path": log,
                    "events": Path(os.path.relpath(event, metadata)).as_posix(),
                    "scored_gold": Path(os.path.relpath(scored, metadata)).as_posix(),
                    "proof": Path(os.path.relpath(proof, metadata)).as_posix(),
                }
            )
    synthetic_md5 = hashlib.md5(archive.read_bytes()).hexdigest()
    monkeypatch.setattr(taxonomy, "_RUSSELL_OFFICIAL_MD5", synthetic_md5)
    monkeypatch.setattr(builder._taxonomy, "_RUSSELL_OFFICIAL_MD5", synthetic_md5)
    for event, gold, join, proof, scored, map_report in pending:
        taxonomy.verify(
            dataset_root=root,
            events=event,
            gold=gold,
            join_report=join,
            archive=archive,
            time_from="2022-01-21T00:00:00Z",
            time_to="2022-01-25T00:00:00Z",
            output=proof,
        )
        taxonomy.map_gold(gold=gold, proof=proof, output=scored, report=map_report)
    config = metadata / "sources.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "dataset_id": DATASET,
                "scenario": "russellmitchell",
                "split": "development",
                "sources": source_entries,
            }
        ),
        encoding="utf-8",
    )
    splits = metadata / "splits.json"
    splits.write_text(
        json.dumps(
            {
                "development": [
                    "fox",
                    "harrison",
                    "russellmitchell",
                    "santos",
                    "wheeler",
                ],
                "validation": ["wardbeck"],
                "test": ["shaw", "wilson"],
            }
        ),
        encoding="utf-8",
    )
    return builder, config, splits, source_entries


def build(builder, config, splits, output):
    return builder.build_case(
        source_config=config,
        splits=splits,
        case_id="russell-dev-001",
        time_from="2022-01-23T12:00:01Z",
        time_to="2022-01-23T12:00:04Z",
        output_dir=output,
    )


def test_russell_three_sources_build_and_rebuild_identically(russell_sources, tmp_path):
    builder, config, splits, _ = russell_sources
    output = tmp_path / "russell-case"
    result = build(builder, config, splits, output)
    assert result["event_count"] == 3
    agent = json.loads((output / "agent/manifest.json").read_text(encoding="utf-8"))
    manifest = json.loads(
        (output / "scoring/manifest.json").read_text(encoding="utf-8")
    )
    assert agent["dataset_id"] == manifest["dataset_id"] == DATASET
    assert agent["scenario"] == manifest["scenario"] == "russellmitchell"
    assert agent["generator_version"] == "ait-russellmitchell-agent-case-v2"
    assert manifest["generator_version"] == "ait-russellmitchell-development-case-v2"
    assert set(manifest["counts"]["per_source"]) == set(LOGS)
    assert manifest["counts"]["attack"] == 3
    assert manifest["counts"]["types"] == {
        "reconnaissance": 0,
        "credential_attack": 0,
        "webshell_upload": 0,
        "remote_command_execution": 1,
        "privilege_escalation": 1,
        "data_exfiltration": 1,
    }
    agent_rows = [
        json.loads(row)
        for row in (output / "agent/events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    scored_rows = [
        json.loads(row)
        for row in (output / "scoring/gold.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert [row["relative_log_path"] for row in agent_rows] == list(LOGS)
    assert all(row["is_attack"] is True for row in scored_rows)
    assert all("labels" not in row and "is_attack" not in row for row in agent_rows)
    source_gold = json.loads(
        (output / "scoring/source-gold.json").read_text(encoding="utf-8")
    )
    roles = {row["role"] for row in source_gold["observed_source_ips"]}
    assert roles == {"http_client", "dns_query_client"}
    assert set(manifest["input_sha256"]) >= {
        str(config.resolve()),
        str(splits.resolve()),
    }
    rebuilt = tmp_path / "russell-rebuilt"
    builder.rebuild_case(manifest=output / "scoring/manifest.json", output_dir=rebuilt)
    for name in ARTIFACTS:
        assert (output / name).read_bytes() == (rebuilt / name).read_bytes()


@pytest.mark.parametrize("mutation", ["scenario", "split", "legacy", "wrong_proof"])
def test_russell_rejects_mismatched_config_or_proof(
    russell_sources, tmp_path, mutation
):
    builder, config, splits, entries = russell_sources
    value = json.loads(config.read_text(encoding="utf-8"))
    if mutation == "scenario":
        value["scenario"] = "fox"
    elif mutation == "split":
        value["split"] = "test"
    elif mutation == "legacy":
        value["schema_version"] = 1
    else:
        value["sources"][0]["proof"] = entries[1]["proof"]
    config.write_text(json.dumps(value), encoding="utf-8")
    output = tmp_path / f"bad-{mutation}"
    with pytest.raises(ValueError):
        build(builder, config, splits, output)
    assert not output.exists()


def test_russell_shared_log_rejects_fox_dataset_config(russell_sources, tmp_path):
    builder, config, splits, entries = russell_sources
    value = json.loads(config.read_text(encoding="utf-8"))
    value["dataset_id"] = "ait-v2.1:fox"
    value["scenario"] = "fox"
    value["sources"] = [entries[1]]
    config.write_text(json.dumps(value), encoding="utf-8")
    output = tmp_path / "cross-scene"
    with pytest.raises(ValueError, match="dataset|proof|profile"):
        build(builder, config, splits, output)
    assert not output.exists()


@pytest.mark.parametrize(
    ("source_index", "mutation"),
    [(0, "extra"), (1, "extra"), (2, "extra"), (0, "rewrite")],
)
def test_russell_rejects_forged_agent_event_even_with_updated_proof_hash(
    russell_sources, tmp_path, monkeypatch, source_index, mutation
):
    builder, config, splits, entries = russell_sources
    entry = entries[source_index]
    event_path = (config.parent / entry["events"]).resolve()
    proof_path = (config.parent / entry["proof"]).resolve()
    event = json.loads(event_path.read_text(encoding="utf-8"))
    if mutation == "extra":
        event["answer_hint"] = "forged"
    else:
        event["http_status"] = 503
    event_path.write_text(json.dumps(event) + "\n", encoding="utf-8")
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    proof["inputs"]["events"]["sha256"] = hashlib.sha256(
        event_path.read_bytes()
    ).hexdigest()
    proof_path.write_text(json.dumps(proof), encoding="utf-8")

    # Exercise the builder's raw-source comparison independently of the
    # taxonomy loader's own defense, while retaining its prechecked file hashes.
    def accept_bound_proof(path, gold):
        loaded = json.loads(Path(path).read_text(encoding="utf-8"))
        paths = builder._taxonomy._paths(
            {key: value["path"] for key, value in loaded["inputs"].items()}
        )
        return loaded, paths, Path(path).resolve()

    monkeypatch.setattr(builder._taxonomy, "_load_proof", accept_bound_proof)
    output = tmp_path / f"forged-{source_index}-{mutation}"
    with pytest.raises(ValueError, match="Agent event differs from raw source"):
        build(builder, config, splits, output)
    assert not output.exists()


@pytest.mark.parametrize("split", ["validation", "test"])
def test_reviewed_non_development_split_builds_and_rebuilds(
    russell_sources, tmp_path, monkeypatch, split
):
    builder, config, splits, _ = russell_sources
    split_data = json.loads(splits.read_text(encoding="utf-8"))
    split_data["development"].remove("russellmitchell")
    split_data[split].append("russellmitchell")
    splits.write_text(json.dumps(split_data), encoding="utf-8")
    monkeypatch.setattr(builder, "_SPLITS", split_data)
    config_data = json.loads(config.read_text(encoding="utf-8"))
    config_data["split"] = split
    config.write_text(json.dumps(config_data), encoding="utf-8")

    output = tmp_path / f"russell-{split}-case"
    result = builder.build_case(
        source_config=config,
        splits=splits,
        case_id=f"russell-{split}-001",
        time_from="2022-01-23T12:00:01Z",
        time_to="2022-01-23T12:00:04Z",
        output_dir=output,
    )
    assert result["event_count"] == 3
    agent = json.loads((output / "agent/manifest.json").read_text(encoding="utf-8"))
    scoring = json.loads(
        (output / "scoring/manifest.json").read_text(encoding="utf-8")
    )
    assert agent["split"] == scoring["split"] == split
    assert scoring["generator_version"] == f"ait-russellmitchell-{split}-case-v2"
    rebuilt = tmp_path / f"russell-{split}-rebuilt"
    builder.rebuild_case(manifest=output / "scoring/manifest.json", output_dir=rebuilt)
    for name in ARTIFACTS:
        assert (output / name).read_bytes() == (rebuilt / name).read_bytes()
