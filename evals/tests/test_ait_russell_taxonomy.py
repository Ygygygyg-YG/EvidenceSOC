import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "datasets/ait_v2/taxonomy.py"
DATASET = "ait-v2.1:russellmitchell"
FOX = "ait-v2.1:fox"
APACHE = "intranet_server/logs/apache2/intranet.smith.russellmitchell.com-access.log.2"
AUDIT = "intranet_server/logs/audit/audit.log"
DNS = "inet-firewall/logs/dnsmasq.log"


@pytest.fixture
def taxonomy():
    spec = importlib.util.spec_from_file_location("russell_taxonomy_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def row(log, label, rule, dataset=DATASET):
    return {
        "dataset_id": dataset,
        "relative_log_path": log,
        "labels": [label],
        "rules": {label: [rule]},
    }


@pytest.mark.parametrize(
    "log,label,rule,expected",
    [
        (APACHE, "dirb", "attacker.dirb.time", "reconnaissance"),
        (APACHE, "service_scan", "attacker.service_scan", "reconnaissance"),
        (APACHE, "wpscan", "attacker.wpscan.time", "reconnaissance"),
        (APACHE, "webshell_upload", "attacker.webshell.upload.seq", "webshell_upload"),
        (
            APACHE,
            "webshell_cmd",
            "attacker.escalate.webshell.cmd.http",
            "remote_command_execution",
        ),
        (
            APACHE,
            "webshell_cmd",
            "attacker.escalate.webshell.cmd.http_prepare_crack",
            "remote_command_execution",
        ),
        (
            AUDIT,
            "attacker_change_user",
            "attacker.escalate.audit.su.login",
            "privilege_escalation",
        ),
        (
            AUDIT,
            "escalated_sudo_command",
            "attacker.escalate.audit.sudo.command.start",
            "privilege_escalation",
        ),
        (
            AUDIT,
            "escalated_sudo_command",
            "attacker.escalate.audit.sudo.command.events",
            "privilege_escalation",
        ),
        (DNS, "dirb", "attacker_foothold_dnsmasq_dirb_parent_query", "reconnaissance"),
        (DNS, "dirb", "attacker_foothold_dnsmasq_dirb_sub_query", "reconnaissance"),
        (DNS, "dnsteal", "dnsteal.domain.match", "data_exfiltration"),
        (DNS, "dnsteal-received", "dnsteal.domain.received", "data_exfiltration"),
        (DNS, "dns_scan", "attacker.foothold.dnsmasq.dns_scan_probe", "reconnaissance"),
        (
            DNS,
            "network_scan",
            "attacker_foothold_dnsmasq_nmap_scan_sub_query",
            "reconnaissance",
        ),
    ],
)
def test_reviewed_russell_pairs(taxonomy, log, label, rule, expected):
    mapped = taxonomy.classify_record(row(log, label, rule))
    assert mapped["attack_types"] == [expected]
    assert mapped["mapping_evidence"] == [
        {"label": label, "rule": rule, "attack_type": expected}
    ]
    assert mapped["taxonomy_version"].startswith("russellmitchell-")


@pytest.mark.parametrize(
    "log,label,rule",
    [
        (APACHE, "foothold", "attacker.service_scan"),
        (APACHE, "escalate", "attacker.escalate.webshell.cmd.http_prepare_crack"),
        (AUDIT, "escalate", "attacker.escalate.audit.su.login"),
        (AUDIT, "CRED_ACQ", "attacker.escalate.audit.su.login"),
        (AUDIT, "credential_attack", "local.authentication"),
        (DNS, "webshell_cmd", "attacker.foothold.dnsmasq.webshell"),
        (DNS, "dnsteal-dropped", "dnsteal.domain.dropped"),
        (DNS, "dnsteal-dropped", "dnsteal.domain.dropped-retry"),
        (DNS, "attacker", "dnsteal.domain.match"),
        (DNS, "dirb", "attacker_foothold_dnsmasq_dirb_parent_query.new"),
    ],
)
def test_broad_or_unreviewed_pairs_remain_attack_without_inferred_type(
    taxonomy, log, label, rule
):
    mapped = taxonomy.classify_record(row(log, label, rule))
    assert mapped["is_attack"] is True
    assert mapped["attack_types"] == []
    assert mapped["unmapped_labels"] == [label]


@pytest.mark.parametrize(
    "log,label,rule",
    [
        (AUDIT, "attacker_change_user", "attacker.escalate.audit.su.login"),
        (DNS, "dirb", "attacker_foothold_dnsmasq_dirb_sub_query"),
    ],
)
def test_identical_log_path_does_not_enable_russell_rules_for_fox(
    taxonomy, log, label, rule
):
    assert taxonomy.classify_record(row(log, label, rule, FOX))["attack_types"] == []
    assert taxonomy.classify_record(row(log, label, rule))["attack_types"]


@pytest.mark.parametrize(
    "dataset,log",
    [
        ("ait-v2.1:unknown", DNS),
        (None, DNS),
        ([], DNS),
        (FOX, APACHE),
        (DATASET, "intranet_server/logs/apache2/intranet.price.fox.org-access.log.2"),
        (DATASET, None),
        (DATASET, []),
    ],
)
def test_unknown_scenario_or_cross_scenario_source_is_rejected(taxonomy, dataset, log):
    with pytest.raises(ValueError):
        taxonomy.classify_record(
            {"dataset_id": dataset, "relative_log_path": log, "labels": [], "rules": {}}
        )


@pytest.fixture(params=[APACHE, AUDIT, DNS])
def bundle(taxonomy, tmp_path, monkeypatch, request):
    log = request.param
    root = tmp_path / "raw"
    source, labels = root / "gather" / log, root / "labels" / log
    source.parent.mkdir(parents=True)
    labels.parent.mkdir(parents=True)
    if log == APACHE:
        text = '10.0.0.1 - - [21/Jan/2022:12:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "test"\n'
        label, rule_name = "dirb", "attacker.dirb.time"
        parse = taxonomy._parser.parse_apache_file
    elif log == AUDIT:
        text = "type=USER_AUTH msg=audit(1642766400.071:42): fixture\n"
        label, rule_name = "attacker_change_user", "attacker.escalate.audit.su.login"
        parse = taxonomy._audit_parser.parse_audit_file
    else:
        text = "Jan 21 12:00:00 dnsmasq[42]: query[A] example.test from 192.0.2.1\n"
        label, rule_name = "dirb", "attacker_foothold_dnsmasq_dirb_parent_query"
        parse = taxonomy._dns_parser.parse_dnsmasq_file
    source.write_bytes((text * 2).encode())
    labels.write_text(
        json.dumps({"line": 1, "labels": [label], "rules": {label: [rule_name]}})
        + "\n",
        encoding="utf-8",
    )
    events = tmp_path / "agent" / "events.jsonl"
    args = {
        "dataset_root": root,
        "dataset_id": DATASET,
        "relative_log_path": log,
        "output": events,
        "errors": tmp_path / "errors.jsonl",
    }
    if log == DNS:
        args.update(year=2022, utc_offset="+00:00")
    parse(**args)
    gold, report = tmp_path / "gold.jsonl", tmp_path / "join.json"
    taxonomy._join.join_labels(
        dataset_root=root,
        dataset_id=DATASET,
        relative_log_path=log,
        events=events,
        output=gold,
        report=report,
    )
    archive = tmp_path / "russell.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.write(source, "russellmitchell/gather/" + log)
        z.write(labels, "russellmitchell/labels/" + log)
    monkeypatch.setattr(
        taxonomy,
        "_RUSSELL_OFFICIAL_MD5",
        hashlib.md5(archive.read_bytes()).hexdigest(),
        raising=False,
    )
    return {
        "dataset_root": root,
        "events": events,
        "gold": gold,
        "join_report": report,
        "archive": archive,
        "time_from": "2022-01-21T00:00:00Z",
        "time_to": "2022-01-25T00:00:00Z",
        "output": tmp_path / "proof.json",
    }


def map_args(bundle, tmp_path):
    return {
        "gold": bundle["gold"],
        "proof": bundle["output"],
        "output": tmp_path / "mapped.jsonl",
        "report": tmp_path / "mapped.json",
    }


def mutate(path, **changes):
    lines = path.read_text(encoding="utf-8").splitlines()
    row_value = (
        json.loads(lines[0])
        if path.suffix == ".jsonl"
        else json.loads(path.read_text(encoding="utf-8"))
    )
    row_value.update(changes)
    if path.suffix == ".jsonl":
        lines[0] = json.dumps(row_value)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        path.write_text(json.dumps(row_value), encoding="utf-8")


def test_complete_russell_proof_and_map(taxonomy, bundle, tmp_path):
    proof = taxonomy.verify(**bundle)
    assert proof["dataset_id"] == DATASET
    assert (
        proof["archive_md5"] == hashlib.md5(bundle["archive"].read_bytes()).hexdigest()
    )
    assert proof["counts"]["raw_line_count"] == 2
    assert proof["counts"]["parse_errors"] == 0
    args = map_args(bundle, tmp_path)
    summary = taxonomy.map_gold(**args)
    assert (
        summary["attack_events"],
        summary["normal_events"],
        summary["unknown_events"],
    ) == (1, 1, 0)
    assert set(summary["type_event_counts"]) == {
        "reconnaissance",
        "credential_attack",
        "webshell_upload",
        "remote_command_execution",
        "privilege_escalation",
        "data_exfiltration",
    }
    rows = [
        json.loads(line)
        for line in args["output"].read_text(encoding="utf-8").splitlines()
    ]
    assert rows[0]["attack_types"]
    assert rows[1]["is_attack"] is False
    assert rows[1]["normal_basis"] == "complete_official_annotation_absence"


@pytest.mark.parametrize(
    "target,change",
    [
        ("events", {"dataset_id": FOX}),
        ("gold", {"dataset_id": FOX}),
        ("events", {"line_number": 2}),
        ("events", {"labels": []}),
        ("events", {"timestamp": "2022-01-20T12:00:00Z"}),
        ("join_report", {"truncated": True}),
        ("join_report", {"labels_complete_read": False}),
        ("join_report", {"unmatched_annotation_lines": 1}),
    ],
)
def test_proof_requires_full_current_source_and_annotation_scope(
    taxonomy, bundle, target, change
):
    mutate(bundle[target], **change)
    with pytest.raises(ValueError):
        taxonomy.verify(**bundle)
    assert not bundle["output"].exists()


@pytest.mark.parametrize(
    "target", ["raw", "labels", "events", "gold", "join_report", "archive"]
)
def test_each_current_input_is_bound_by_proof(taxonomy, bundle, tmp_path, target):
    proof = taxonomy.verify(**bundle)
    path = Path(proof["inputs"][target]["path"])
    with path.open("ab") as stream:
        stream.write(b" ")
    args = map_args(bundle, tmp_path)
    with pytest.raises(ValueError):
        taxonomy.map_gold(**args)
    assert not args["output"].exists()


@pytest.mark.parametrize(
    "changes",
    [
        {"dataset_id": FOX},
        {"dataset_id": "ait-v2.1:unknown"},
        {"archive_md5": "0" * 32},
        {"generator_version": "fox-dnsmasq-taxonomy-v1"},
        {"counts": {"parse_errors": 1}},
    ],
)
def test_tampered_scenario_proof_is_rejected(taxonomy, bundle, tmp_path, changes):
    taxonomy.verify(**bundle)
    mutate(bundle["output"], **changes)
    args = map_args(bundle, tmp_path)
    with pytest.raises(ValueError):
        taxonomy.map_gold(**args)
    assert not args["output"].exists()


def test_forged_input_hash_cannot_replace_official_archive_source(
    taxonomy, bundle, tmp_path
):
    proof = taxonomy.verify(**bundle)
    raw = Path(proof["inputs"]["raw"]["path"])
    with raw.open("ab") as stream:
        stream.write(b"tampered\n")
    proof["inputs"]["raw"]["sha256"] = hashlib.sha256(raw.read_bytes()).hexdigest()
    bundle["output"].write_text(json.dumps(proof), encoding="utf-8")
    args = map_args(bundle, tmp_path)
    with pytest.raises(ValueError):
        taxonomy.map_gold(**args)
    assert not args["output"].exists()


def test_proof_requires_physical_line_coverage_and_bounded_timestamps(taxonomy, bundle):
    lines = bundle["events"].read_text(encoding="utf-8").splitlines()
    bundle["events"].write_text(lines[0] + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        taxonomy.verify(**bundle)
    bundle["events"].write_text("\n".join(lines) + "\n", encoding="utf-8")
    bundle["time_to"] = "2022-01-21T12:00:00Z"
    with pytest.raises(ValueError):
        taxonomy.verify(**bundle)


def test_normal_requires_completeness_and_keeps_legacy_fox_default(taxonomy):
    normal = {
        "dataset_id": DATASET,
        "relative_log_path": DNS,
        "labels": [],
        "rules": {},
        "annotation_status": "unlabeled_unknown",
    }
    assert taxonomy.classify_record(normal)["is_attack"] is None
    assert (
        taxonomy.classify_record(normal, completeness_verified=True)["is_attack"]
        is False
    )
    assert (
        taxonomy.classify_record({"labels": [], "rules": {}})["taxonomy_version"]
        == "fox-apache-taxonomy-v1"
    )


def test_official_scenario_checksums_are_distinct(taxonomy):
    assert taxonomy._OFFICIAL_MD5 == "27b09dd2876ec08ee99a9b53e8718c92"
    assert (
        getattr(taxonomy, "_RUSSELL_OFFICIAL_MD5", None)
        == "abb43a46c70939ad9f98669e3510d2b7"
    )


@pytest.mark.parametrize(
    "field,value",
    [("year", True), ("year", 2023), ("utc_offset", "-00:00"), ("basis", "local")],
)
@pytest.mark.parametrize("bundle", [DNS], indirect=True)
def test_dns_proof_timestamp_parameters_are_exact_and_type_checked(
    taxonomy, bundle, tmp_path, field, value
):
    proof = taxonomy.verify(**bundle)
    proof["timestamp_parameters"][field] = value
    bundle["output"].write_text(json.dumps(proof), encoding="utf-8")
    with pytest.raises(ValueError):
        taxonomy.map_gold(**map_args(bundle, tmp_path))


@pytest.mark.parametrize(
    "field", ["mapping_evidence", "taxonomy_version", "normal_basis", "unmapped_labels"]
)
def test_agent_events_cannot_contain_taxonomy_truth(taxonomy, bundle, field):
    mutate(bundle["events"], **{field: []})
    with pytest.raises(ValueError):
        taxonomy.verify(**bundle)


def test_archive_md5_is_checked_before_proof(taxonomy, bundle):
    with bundle["archive"].open("ab") as stream:
        stream.write(b"changed")
    with pytest.raises(ValueError, match="MD5"):
        taxonomy.verify(**bundle)


def test_russell_observable_fields_must_match_source(taxonomy, bundle):
    mutate(bundle["events"], raw_line="fabricated observable source")
    with pytest.raises(ValueError):
        taxonomy.verify(**bundle)


def test_forged_gold_hash_cannot_change_original_annotation(taxonomy, bundle, tmp_path):
    proof = taxonomy.verify(**bundle)
    mutate(
        bundle["gold"],
        labels=["unreviewed_attack"],
        rules={"unreviewed_attack": ["invented.rule"]},
    )
    proof["inputs"]["gold"]["sha256"] = hashlib.sha256(
        bundle["gold"].read_bytes()
    ).hexdigest()
    bundle["output"].write_text(json.dumps(proof), encoding="utf-8")
    args = map_args(bundle, tmp_path)
    with pytest.raises(ValueError):
        taxonomy.map_gold(**args)
    assert not args["output"].exists() and not args["report"].exists()


@pytest.mark.parametrize(
    "field,value",
    [("answer_hint", "attacker supplied answer"), ("unexpected_metric", 42)],
)
def test_russell_agent_field_set_must_equal_parser_output(
    taxonomy, bundle, field, value
):
    mutate(bundle["events"], **{field: value})
    with pytest.raises(ValueError, match="observation"):
        taxonomy.verify(**bundle)
    assert not bundle["output"].exists()


@pytest.mark.parametrize(
    "changes", [{"answer_hint": "attacker supplied answer"}, {"raw_line": "fabricated"}]
)
def test_forged_event_hash_cannot_authorize_agent_payload(
    taxonomy, bundle, tmp_path, changes
):
    proof = taxonomy.verify(**bundle)
    mutate(bundle["events"], **changes)
    proof["inputs"]["events"]["sha256"] = hashlib.sha256(
        bundle["events"].read_bytes()
    ).hexdigest()
    bundle["output"].write_text(json.dumps(proof), encoding="utf-8")
    args = map_args(bundle, tmp_path)
    with pytest.raises(ValueError, match="observation"):
        taxonomy.map_gold(**args)
    assert not args["output"].exists() and not args["report"].exists()
