"""Reviewed scenario profiles must preserve split and ground-truth isolation."""

import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

BASE = Path(__file__).resolve().parents[1] / "datasets" / "ait_v2"
APACHE = {
    "harrison": "intranet_server/logs/apache2/intranet.mannsmith.harrison.com-access.log.1",
    "santos": "intranet_server/logs/apache2/intranet.smith.santos.com-access.log",
    "wardbeck": "intranet_server/logs/apache2/intranet.hurstwong.wardbeck.info-access.log.1",
    "wheeler": "intranet_server/logs/apache2/intranet.flores.wheeler.biz-access.log.1",
    "shaw": "intranet_server/logs/apache2/intranet.thomasmurray.shaw.info-access.log.2",
    "wilson": "intranet_server/logs/apache2/intranet.hallbrown.wilson.com-access.log.2",
}
AUDIT = "intranet_server/logs/audit/audit.log"
DNS = "inet-firewall/logs/dnsmasq.log"
SPLITS = {
    "development": ["fox", "harrison", "russellmitchell", "santos", "wheeler"],
    "validation": ["wardbeck"],
    "test": ["shaw", "wilson"],
}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("scenario", APACHE)
def test_extended_profiles_and_reviewed_rules(scenario):
    taxonomy = load("extended_taxonomy", BASE / "taxonomy.py")
    builder = load("extended_builder", BASE / "build_manifests.py")
    dataset = f"ait-v2.1:{scenario}"
    assert set(taxonomy._SCENARIOS[dataset]) == {APACHE[scenario], AUDIT, DNS}
    assert set(builder._SCENARIOS[dataset]["profiles"]) == {
        APACHE[scenario],
        AUDIT,
        DNS,
    }
    assert taxonomy._official_md5(dataset) != taxonomy._OFFICIAL_MD5
    attack = taxonomy.classify_record(
        {
            "dataset_id": dataset,
            "relative_log_path": APACHE[scenario],
            "labels": ["dirb"],
            "rules": {"dirb": ["attacker.dirb.time"]},
        }
    )
    assert attack["attack_types"] == ["reconnaissance"]
    unsupported = taxonomy.classify_record(
        {
            "dataset_id": dataset,
            "relative_log_path": DNS,
            "labels": ["webshell_cmd"],
            "rules": {"webshell_cmd": ["attacker.foothold.dnsmasq.webshell"]},
        }
    )
    assert unsupported["is_attack"] is True
    assert unsupported["attack_types"] == []


def test_wardbeck_validation_build_rebuild_and_agent_isolation(tmp_path, monkeypatch):
    taxonomy = load("wardbeck_taxonomy", BASE / "taxonomy.py")
    builder = load("wardbeck_builder", BASE / "build_manifests.py")
    dataset = "ait-v2.1:wardbeck"
    log = APACHE["wardbeck"]
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    raw_root = inputs / "raw"
    raw = raw_root / "gather" / log
    labels = raw_root / "labels" / log
    raw.parent.mkdir(parents=True)
    labels.parent.mkdir(parents=True)
    line = b'192.0.2.8 - - [20/Jan/2022:12:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "fixture"\n'
    raw.write_bytes(line * 2)
    labels.write_text(
        json.dumps(
            {
                "line": 1,
                "labels": ["dirb"],
                "rules": {"dirb": ["attacker.dirb.time"]},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    archive = inputs / "wardbeck.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.write(raw, "wardbeck/gather/" + log)
        bundle.write(labels, "wardbeck/labels/" + log)
    md5 = hashlib.md5(archive.read_bytes()).hexdigest()
    monkeypatch.setitem(taxonomy._EXTENDED_OFFICIAL_MD5, dataset, md5)
    monkeypatch.setitem(builder._taxonomy._EXTENDED_OFFICIAL_MD5, dataset, md5)
    events = inputs / "agent" / "events.jsonl"
    gold = inputs / "gold.jsonl"
    join = inputs / "join.json"
    proof = inputs / "proof.json"
    scored = inputs / "scored.jsonl"
    taxonomy._parser.parse_apache_file(
        dataset_root=raw_root,
        dataset_id=dataset,
        relative_log_path=log,
        output=events,
        errors=inputs / "errors.jsonl",
    )
    taxonomy._join.join_labels(
        dataset_root=raw_root,
        dataset_id=dataset,
        relative_log_path=log,
        events=events,
        output=gold,
        report=join,
    )
    taxonomy.verify(
        dataset_root=raw_root,
        events=events,
        gold=gold,
        join_report=join,
        archive=archive,
        time_from="2022-01-19T00:00:00Z",
        time_to="2022-01-24T00:00:00Z",
        output=proof,
    )
    taxonomy.map_gold(
        gold=gold,
        proof=proof,
        output=scored,
        report=inputs / "map.json",
    )
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    config = metadata / "sources.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": 2,
                "dataset_id": dataset,
                "scenario": "wardbeck",
                "split": "validation",
                "sources": [
                    {
                        "relative_log_path": log,
                        "events": str(events),
                        "scored_gold": str(scored),
                        "proof": str(proof),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    # Source entries must remain relative even when the data is outside metadata/.
    payload = json.loads(config.read_text(encoding="utf-8"))
    for key, path in (("events", events), ("scored_gold", scored), ("proof", proof)):
        payload["sources"][0][key] = "../inputs/" + path.name
    # The Agent events live in their own directory.
    payload["sources"][0]["events"] = "../inputs/agent/events.jsonl"
    config.write_text(json.dumps(payload), encoding="utf-8")
    splits = metadata / "splits.json"
    splits.write_text(json.dumps(SPLITS), encoding="utf-8")
    output = tmp_path / "case"
    result = builder.build_case(
        source_config=config,
        splits=splits,
        case_id="wardbeck-validation-001",
        time_from="2022-01-20T12:00:00Z",
        time_to="2022-01-20T12:00:01Z",
        output_dir=output,
    )
    assert result["counts"]["attack"] == 1
    assert result["counts"]["normal"] == 1
    assert (
        json.loads((output / "agent/manifest.json").read_text())["split"]
        == "validation"
    )
    rows = (output / "agent/events.jsonl").read_text().splitlines()
    assert all("attack_types" not in json.loads(row) for row in rows)
    rebuilt = tmp_path / "case-rebuilt"
    builder.rebuild_case(manifest=output / "scoring/manifest.json", output_dir=rebuilt)
    for relative in (
        "agent/events.jsonl",
        "agent/manifest.json",
        "scoring/gold.jsonl",
        "scoring/source-gold.json",
        "scoring/manifest.json",
    ):
        assert (output / relative).read_bytes() == (rebuilt / relative).read_bytes()
