import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "datasets/ait_v2/taxonomy.py"
LOG = "inet-firewall/logs/dnsmasq.log"
PAIRS = [
    ("dnsteal", "dnsteal.domain.match", "data_exfiltration"),
    ("dnsteal-received", "dnsteal.domain.received", "data_exfiltration"),
    ("dns_scan", "attacker.foothold.dnsmasq.dns_scan_probe", "reconnaissance"),
    (
        "dns_scan",
        "attacker_foothold_dnsmasq_dns_brute_scan_parent_query",
        "reconnaissance",
    ),
    (
        "dns_scan",
        "attacker_foothold_dnsmasq_dns_brute_scan_sub_query",
        "reconnaissance",
    ),
    (
        "network_scan",
        "attacker_foothold_dnsmasq_nmap_scan_parent_query",
        "reconnaissance",
    ),
    ("network_scan", "attacker_foothold_dnsmasq_nmap_scan_sub_query", "reconnaissance"),
    (
        "service_scan",
        "attacker_foothold_dnsmasq_service_scan_parent_query",
        "reconnaissance",
    ),
    (
        "service_scan",
        "attacker_foothold_dnsmasq_service_scan_sub_query",
        "reconnaissance",
    ),
    ("traceroute", "attacker.foothold.dnsmasq.traceroute", "reconnaissance"),
    ("wpscan", "attacker.foothold.dnsmasq.wpscan", "reconnaissance"),
]


@pytest.fixture
def taxonomy():
    spec = importlib.util.spec_from_file_location("dns_taxonomy_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def dns_bundle(taxonomy, tmp_path, monkeypatch):
    root = tmp_path / "raw"
    source, labels = root / "gather" / LOG, root / "labels" / LOG
    source.parent.mkdir(parents=True)
    labels.parent.mkdir(parents=True)
    source.write_text(
        "Jan 18 12:00:00 dnsmasq[42]: query[A] example.test from 192.0.2.1\n"
        "Jan 18 12:01:00 dnsmasq[43]: cached example.test is 192.0.2.2\n",
        encoding="utf-8",
    )
    labels.write_text(
        json.dumps(
            {
                "line": 1,
                "labels": ["dnsteal"],
                "rules": {"dnsteal": ["dnsteal.domain.match"]},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    parser_spec = importlib.util.spec_from_file_location(
        "dns_fixture_parser", SCRIPT.with_name("dnsmasq_parse.py")
    )
    parser = importlib.util.module_from_spec(parser_spec)
    parser_spec.loader.exec_module(parser)
    events = tmp_path / "agent" / "events.jsonl"
    parser.parse_dnsmasq_file(
        dataset_root=root,
        dataset_id="ait-v2.1:fox",
        relative_log_path=LOG,
        output=events,
        errors=tmp_path / "errors.jsonl",
        year=2022,
        utc_offset="+00:00",
    )
    gold, join_report = tmp_path / "gold.jsonl", tmp_path / "join.json"
    taxonomy._join.join_labels(
        dataset_root=root,
        dataset_id="ait-v2.1:fox",
        relative_log_path=LOG,
        events=events,
        output=gold,
        report=join_report,
    )
    archive = tmp_path / "fixture.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.write(source, "fixture/gather/" + LOG)
        z.write(labels, "fixture/labels/" + LOG)
    monkeypatch.setattr(
        taxonomy, "_OFFICIAL_MD5", hashlib.md5(archive.read_bytes()).hexdigest()
    )
    return {
        "dataset_root": root,
        "events": events,
        "gold": gold,
        "join_report": join_report,
        "archive": archive,
        "time_from": "2022-01-18T00:00:00Z",
        "time_to": "2022-01-19T00:00:00Z",
        "output": tmp_path / "proof.json",
    }


@pytest.mark.parametrize("label,rule,kind", PAIRS)
def test_exact_dns_pairs(taxonomy, label, rule, kind):
    result = taxonomy.classify_record(
        {"relative_log_path": LOG, "labels": [label], "rules": {label: [rule]}}
    )
    assert result["is_attack"] is True
    assert result["attack_types"] == [kind]
    assert result["mapping_evidence"] == [
        {"label": label, "rule": rule, "attack_type": kind}
    ]


def test_dns_fixture_verify_map_and_timestamp_proof(taxonomy, dns_bundle, tmp_path):
    proof = taxonomy.verify(**dns_bundle)
    assert proof["timestamp_parameters"] == {
        "year": 2022,
        "utc_offset": "+00:00",
        "basis": "explicit_year_and_utc_offset",
    }
    result = taxonomy.map_gold(
        gold=dns_bundle["gold"],
        proof=dns_bundle["output"],
        output=tmp_path / "mapped.jsonl",
        report=tmp_path / "mapped.json",
    )
    assert (
        result["attack_events"],
        result["normal_events"],
        result["unknown_events"],
    ) == (1, 1, 0)
    rows = [
        json.loads(line)
        for line in (tmp_path / "mapped.jsonl").read_text().splitlines()
    ]
    assert rows[0]["attack_types"] == ["data_exfiltration"]
    assert rows[1]["normal_basis"] == "complete_official_annotation_absence"


def test_two_exact_dns_pairs_keep_both_evidences(taxonomy):
    row = {
        "relative_log_path": LOG,
        "labels": ["dnsteal", "dnsteal-received"],
        "rules": {
            "dnsteal": ["dnsteal.domain.match"],
            "dnsteal-received": ["dnsteal.domain.received"],
        },
    }
    result = taxonomy.classify_record(row)
    assert result["attack_types"] == ["data_exfiltration"]
    assert result["mapping_evidence"] == [
        {
            "label": "dnsteal",
            "rule": "dnsteal.domain.match",
            "attack_type": "data_exfiltration",
        },
        {
            "label": "dnsteal-received",
            "rule": "dnsteal.domain.received",
            "attack_type": "data_exfiltration",
        },
    ]


def test_dns_cli_verify_and_limited_map_preview(taxonomy, dns_bundle, tmp_path, capsys):
    proof = tmp_path / "cli-proof.json"
    assert (
        taxonomy.main(
            [
                "verify",
                "--dataset-root",
                str(dns_bundle["dataset_root"]),
                "--events",
                str(dns_bundle["events"]),
                "--gold",
                str(dns_bundle["gold"]),
                "--join-report",
                str(dns_bundle["join_report"]),
                "--archive",
                str(dns_bundle["archive"]),
                "--time-from",
                dns_bundle["time_from"],
                "--time-to",
                dns_bundle["time_to"],
                "--output",
                str(proof),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["read_events"] == 2

    output, report = tmp_path / "preview.jsonl", tmp_path / "preview.json"
    assert (
        taxonomy.main(
            [
                "map",
                "--gold",
                str(dns_bundle["gold"]),
                "--proof",
                str(proof),
                "--output",
                str(output),
                "--report",
                str(report),
                "--max-events",
                "1",
            ]
        )
        == 0
    )
    summary = json.loads(capsys.readouterr().out)
    assert summary["read_events"] == 1
    assert summary["truncated"] is True
    assert len(output.read_text(encoding="utf-8").splitlines()) == 1
    assert json.loads(report.read_text(encoding="utf-8")) == summary


@pytest.mark.parametrize(
    "row_index,field,value",
    [
        (0, "dnsmasq_pid", "42"),
        (0, "dns_query_type", "AAAA"),
        (0, "dns_query_client", "198.51.100.2"),
        (0, "source_ip", "198.51.100.2"),
        (0, "message", "tampered"),
        (0, "raw_line", "tampered"),
        (0, "raw_line_sha256", "0" * 64),
        (0, "timestamp_year", 2023),
        (0, "timestamp_year", True),
        (0, "timestamp_utc_offset", "+01:00"),
        (0, "timestamp_basis", "guessed"),
        (0, "dns_payload", "tampered"),
        (0, "dns_question_name", "tampered"),
        (1, "dns_query_client", "198.51.100.2"),
        (1, "source_ip", "198.51.100.2"),
    ],
)
def test_verify_rejects_tampered_dns_observation(
    taxonomy, dns_bundle, row_index, field, value
):
    lines = dns_bundle["events"].read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[row_index])
    row[field] = value
    lines[row_index] = json.dumps(row)
    dns_bundle["events"].write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        taxonomy.verify(**dns_bundle)
    assert not dns_bundle["output"].exists()


@pytest.mark.parametrize(
    "row_index,field",
    [
        (0, "dnsmasq_pid"),
        (0, "dns_query_type"),
        (0, "dns_query_client"),
        (0, "source_ip"),
        (0, "message"),
        (0, "raw_line"),
        (0, "timestamp_year"),
        (0, "timestamp_utc_offset"),
        (0, "timestamp_basis"),
        (1, "dns_query_type"),
        (1, "dns_question_name"),
        (1, "dns_query_client"),
        (1, "source_ip"),
    ],
)
def test_verify_rejects_missing_dns_observation_field(
    taxonomy, dns_bundle, row_index, field
):
    lines = dns_bundle["events"].read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[row_index])
    del row[field]
    lines[row_index] = json.dumps(row)
    dns_bundle["events"].write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="DNS event/gold observation"):
        taxonomy.verify(**dns_bundle)
    assert not dns_bundle["output"].exists()


@pytest.mark.parametrize(
    "change",
    [
        lambda proof: proof.pop("timestamp_parameters"),
        lambda proof: proof["timestamp_parameters"].update(year=True),
        lambda proof: proof["timestamp_parameters"].update(utc_offset="-00:00"),
        lambda proof: proof["timestamp_parameters"].update(basis="system_local"),
        lambda proof: proof["timestamp_parameters"].update(extra="value"),
        lambda proof: proof.update(
            relative_log_path="intranet_server/logs/audit/audit.log"
        ),
    ],
)
def test_map_rejects_tampered_dns_proof(taxonomy, dns_bundle, tmp_path, change):
    taxonomy.verify(**dns_bundle)
    proof = json.loads(dns_bundle["output"].read_text(encoding="utf-8"))
    change(proof)
    dns_bundle["output"].write_text(json.dumps(proof), encoding="utf-8")
    with pytest.raises(ValueError):
        taxonomy.map_gold(
            gold=dns_bundle["gold"],
            proof=dns_bundle["output"],
            output=tmp_path / "mapped.jsonl",
            report=tmp_path / "mapped.json",
        )
    assert not (tmp_path / "mapped.jsonl").exists()


def test_map_rejects_dns_proof_swapped_to_other_profile(taxonomy, dns_bundle, tmp_path):
    taxonomy.verify(**dns_bundle)
    proof = json.loads(dns_bundle["output"].read_text(encoding="utf-8"))
    proof["relative_log_path"] = "intranet_server/logs/audit/audit.log"
    proof["taxonomy_version"] = "fox-intranet-audit-taxonomy-v1"
    dns_bundle["output"].write_text(json.dumps(proof), encoding="utf-8")
    with pytest.raises(ValueError):
        taxonomy.map_gold(
            gold=dns_bundle["gold"],
            proof=dns_bundle["output"],
            output=tmp_path / "mapped.jsonl",
            report=tmp_path / "mapped.json",
        )
    assert not (tmp_path / "mapped.jsonl").exists()


def test_dns_scope_and_broad_rules_do_not_infer_types(taxonomy):
    with pytest.raises(ValueError):
        taxonomy.classify_record(
            {
                "relative_log_path": "inet-firewall/logs/other.log",
                "labels": [],
                "rules": {},
            }
        )
    row = {
        "relative_log_path": LOG,
        "labels": ["attacker", "foothold", "dnsteal-received"],
        "rules": {
            "attacker": ["attacker.foothold.dnsmasq.dns_scan_probe"],
            "foothold": ["attacker.foothold.dnsmasq.wpscan"],
            "dnsteal-received": ["dnsteal.domain.received"],
        },
    }
    mapped = taxonomy.classify_record(row)
    assert mapped["attack_types"] == ["data_exfiltration"]
    assert mapped["unmapped_labels"] == ["attacker", "foothold"]


def test_dns_unlabeled_requires_proof_and_apache_default_is_unchanged(taxonomy):
    normal = {
        "relative_log_path": LOG,
        "labels": [],
        "rules": {},
        "annotation_status": "unlabeled_unknown",
    }
    assert taxonomy.classify_record(normal)["is_attack"] is None
    assert (
        taxonomy.classify_record(normal, completeness_verified=True)["is_attack"]
        is False
    )
    legacy = taxonomy.classify_record(
        {"labels": ["dirb"], "rules": {"dirb": ["attacker.dirb.time"]}}
    )
    assert legacy["taxonomy_version"] == "fox-apache-taxonomy-v1"


def test_dns_webshell_command_pair_remains_unmapped_in_dns_scope(taxonomy):
    row = {
        "relative_log_path": LOG,
        "labels": ["webshell_cmd"],
        "rules": {"webshell_cmd": ["attacker.escalate.webshell.cmd.http"]},
    }
    result = taxonomy.classify_record(row)
    assert result["is_attack"] is True
    assert result["attack_types"] == []
    assert result["unmapped_labels"] == ["webshell_cmd"]
