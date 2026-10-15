import hashlib
import importlib.util
import json
import os
import shutil
import zipfile
from pathlib import Path

import pytest

BASE = Path(__file__).resolve().parents[1] / "datasets/ait_v2"
LOGS = (
    "intranet_server/logs/apache2/intranet.price.fox.org-access.log.2",
    "intranet_server/logs/audit/audit.log",
    "inet-firewall/logs/dnsmasq.log",
)
START_RULE = "attacker.escalate.audit.sudo.command.start"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def modules():
    return load("case_taxonomy", BASE / "taxonomy.py"), load(
        "case_builder", BASE / "build_manifests.py"
    )


@pytest.fixture
def source_config(tmp_path, monkeypatch, request):
    taxonomy = load("fixture_taxonomy", BASE / "taxonomy.py")
    early_dns = getattr(request, "param", None) == "early_dns"
    root = tmp_path / "raw"
    archive = tmp_path / "archives" / "fox.zip"
    archive.parent.mkdir()
    specs = [
        (
            LOGS[0],
            b'192.0.2.8 - - [18/Jan/2022:12:00:01 +0000] "GET /x HTTP/1.1" 200 1 "-" "fixture"\n',
            [("webshell_cmd", "attacker.escalate.webshell.cmd.http")],
        ),
        (
            LOGS[1],
            b"type=USER_CMD msg=audit(1642507202.000:42): fixture\n",
            [("escalated_sudo_command", START_RULE)],
        ),
        (
            LOGS[2],
            (
                b"Jan 16 12:00:03 dnsmasq[42]: query[A] example.test from 192.0.2.9\n"
                if early_dns
                else b"Jan 18 12:00:03 dnsmasq[42]: query[A] example.test from 192.0.2.9\n"
            ),
            [("dnsteal", "dnsteal.domain.match")],
        ),
    ]
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    source_entries, pending = [], []
    with zipfile.ZipFile(archive, "w") as z:
        for ix, (log, raw, annotations) in enumerate(specs):
            raw_path, label_path = root / "gather" / log, root / "labels" / log
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            label_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_bytes(raw)
            label, rule = annotations[0]
            label_path.write_text(
                json.dumps({"line": 1, "labels": [label], "rules": {label: [rule]}})
                + "\n"
            )
            z.write(raw_path, "fox/gather/" + log)
            z.write(label_path, "fox/labels/" + log)
            agent_dir = tmp_path / f"agent-{ix}"
            agent_dir.mkdir()
            events = agent_dir / "events.jsonl"
            if ix == 0:
                taxonomy._parser.parse_apache_file(
                    dataset_root=root,
                    dataset_id="ait-v2.1:fox",
                    relative_log_path=log,
                    output=events,
                    errors=tmp_path / f"err-{ix}",
                )
            elif ix == 1:
                load("fixture_audit_parser", BASE / "audit_parse.py").parse_audit_file(
                    dataset_root=root,
                    dataset_id="ait-v2.1:fox",
                    relative_log_path=log,
                    output=events,
                    errors=tmp_path / f"err-{ix}",
                )
            else:
                load(
                    "fixture_dns_parser", BASE / "dnsmasq_parse.py"
                ).parse_dnsmasq_file(
                    dataset_root=root,
                    dataset_id="ait-v2.1:fox",
                    relative_log_path=log,
                    output=events,
                    errors=tmp_path / f"err-{ix}",
                    year=2022,
                    utc_offset="+00:00",
                )
            for folder in ("original-gold", "scored", "proofs"):
                (tmp_path / folder).mkdir(exist_ok=True)
            gold = tmp_path / "original-gold" / f"gold-{ix}.jsonl"
            join = tmp_path / "original-gold" / f"join-{ix}.json"
            taxonomy._join.join_labels(
                dataset_root=root,
                dataset_id="ait-v2.1:fox",
                relative_log_path=log,
                events=events,
                output=gold,
                report=join,
            )
            scored, map_report = (
                tmp_path / "scored" / f"scored-{ix}.jsonl",
                tmp_path / "scored" / f"map-{ix}.json",
            )
            proof = tmp_path / "proofs" / f"proof-{ix}.json"
            pending.append((events, gold, join, scored, map_report, proof))
            source_entries.append(
                {
                    "relative_log_path": log,
                    "events": Path(os.path.relpath(events, metadata_dir)).as_posix(),
                    "scored_gold": Path(
                        os.path.relpath(scored, metadata_dir)
                    ).as_posix(),
                    "proof": Path(os.path.relpath(proof, metadata_dir)).as_posix(),
                }
            )
    monkeypatch.setattr(
        taxonomy, "_OFFICIAL_MD5", hashlib.md5(archive.read_bytes()).hexdigest()
    )
    for ix, (events, gold, join, scored, map_report, proof) in enumerate(pending):
        taxonomy.verify(
            dataset_root=root,
            events=events,
            gold=gold,
            join_report=join,
            archive=archive,
            time_from=(
                "2022-01-15T00:00:00Z"
                if early_dns and ix == 2
                else "2022-01-18T00:00:00Z"
            ),
            time_to=(
                "2022-01-20T00:00:00Z"
                if early_dns and ix == 2
                else "2022-01-19T00:00:00Z"
            ),
            output=proof,
        )
        taxonomy.map_gold(gold=gold, proof=proof, output=scored, report=map_report)
    # The implementation loads its own taxonomy module; keep the fixture's test MD5 authoritative.
    config = metadata_dir / "sources.json"
    config.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "dataset_id": "ait-v2.1:fox",
                "scenario": "fox",
                "split": "development",
                "sources": source_entries,
            }
        ),
        encoding="utf-8",
    )
    return config


def test_build_selects_by_time_and_rebuilds_identically(
    modules, source_config, tmp_path, monkeypatch
):
    taxonomy, builder = modules
    # Both imported modules use their own taxonomy load; fixture helper patches official MD5 there.
    archive_md5 = hashlib.md5((tmp_path / "archives/fox.zip").read_bytes()).hexdigest()
    monkeypatch.setattr(taxonomy, "_OFFICIAL_MD5", archive_md5)
    monkeypatch.setattr(builder._taxonomy, "_OFFICIAL_MD5", archive_md5)
    splits = split_file(tmp_path)
    output = tmp_path / "case"
    result = builder.build_case(
        source_config=source_config,
        splits=splits,
        case_id="fox-dev-001",
        time_from="2022-01-18T12:00:01Z",
        time_to="2022-01-18T12:00:04Z",
        output_dir=output,
    )
    agent_rows = [
        json.loads(line)
        for line in (output / "agent/events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    score_rows = [
        json.loads(line)
        for line in (output / "scoring/gold.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert len(agent_rows) == len(score_rows) == 3
    assert [r["relative_log_path"] for r in agent_rows] == list(LOGS)
    assert [r["is_attack"] for r in score_rows] == [True, True, True]
    assert result["event_count"] == 3
    source_gold = json.loads(
        (output / "scoring/source-gold.json").read_text(encoding="utf-8")
    )
    assert source_gold["scope"] == "selected_window"
    assert source_gold["subsequent_hosts"] == {
        "status": "not_observed",
        "values": [],
        "evidence_ids": [],
    }
    rebuilt = tmp_path / "rebuilt"
    builder.rebuild_case(manifest=output / "scoring/manifest.json", output_dir=rebuilt)
    for rel in (
        "agent/events.jsonl",
        "agent/manifest.json",
        "scoring/gold.jsonl",
        "scoring/source-gold.json",
        "scoring/manifest.json",
    ):
        assert (output / rel).read_bytes() == (rebuilt / rel).read_bytes()


def test_invalid_case_leaves_output_absent(modules, source_config, tmp_path):
    _, builder = modules
    splits = tmp_path / "splits.json"
    splits.write_text(
        json.dumps(
            {"development": ["fox"], "validation": ["wardbeck"], "test": ["shaw"]}
        ),
        encoding="utf-8",
    )
    output = tmp_path / "case"
    with pytest.raises(ValueError):
        builder.build_case(
            source_config=source_config,
            splits=splits,
            case_id="../fox",
            time_from="2022-01-18T12:00:01Z",
            time_to="2022-01-18T12:00:04Z",
            output_dir=output,
        )
    assert not output.exists()


def split_file(tmp_path):
    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir(exist_ok=True)
    splits = metadata_dir / "splits.json"
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
    return splits


def test_half_open_window_excludes_end(modules, source_config, tmp_path, monkeypatch):
    _, builder = modules
    monkeypatch.setattr(
        builder._taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5((tmp_path / "archives/fox.zip").read_bytes()).hexdigest(),
    )
    result = builder.build_case(
        source_config=source_config,
        splits=split_file(tmp_path),
        case_id="fox-dev-boundary",
        time_from="2022-01-18T12:00:01Z",
        time_to="2022-01-18T12:00:03Z",
        output_dir=tmp_path / "bounded",
    )
    assert result["event_count"] == 2
    assert result["counts"]["per_source"][LOGS[2]]["selected"] == 0


def test_scored_gold_type_tampering_fails_and_cleans_output(
    modules, source_config, tmp_path, monkeypatch
):
    _, builder = modules
    monkeypatch.setattr(
        builder._taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5((tmp_path / "archives/fox.zip").read_bytes()).hexdigest(),
    )
    config = json.loads(source_config.read_text(encoding="utf-8"))
    scored_path = source_config.parent / config["sources"][0]["scored_gold"]
    rows = scored_path.read_text(encoding="utf-8").splitlines()
    row = json.loads(rows[0])
    row["is_attack"] = 1
    scored_path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    output = tmp_path / "tampered-output"
    with pytest.raises(ValueError, match="canonical complete mapping"):
        builder.build_case(
            source_config=source_config,
            splits=split_file(tmp_path),
            case_id="fox-dev-tamper",
            time_from="2022-01-18T12:00:01Z",
            time_to="2022-01-18T12:00:04Z",
            output_dir=output,
        )
    assert not output.exists()


def build_args(builder, source_config, tmp_path, output, **overrides):
    args = {
        "source_config": source_config,
        "splits": None,
        "case_id": "fox-dev-contract",
        "time_from": "2022-01-18T12:00:01Z",
        "time_to": "2022-01-18T12:00:04Z",
        "output_dir": output,
    }
    args.update(overrides)
    if args["splits"] is None:
        args["splits"] = split_file(tmp_path)
    return builder.build_case(**args)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", True),
        ("dataset_id", "other"),
        ("scenario", "other"),
        ("split", "test"),
    ],
)
def test_source_config_requires_exact_typed_reviewed_values(
    modules, source_config, tmp_path, field, value
):
    _, builder = modules
    config = json.loads(source_config.read_text(encoding="utf-8"))
    config[field] = value
    source_config.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(ValueError, match="source configuration"):
        build_args(builder, source_config, tmp_path, tmp_path / "bad-config")
    assert not (tmp_path / "bad-config").exists()


@pytest.mark.parametrize("target", ["config", "splits"])
def test_metadata_json_accepts_utf8_bom_without_changing_input_hashes(
    modules, source_config, tmp_path, monkeypatch, target
):
    _, builder = modules
    monkeypatch.setattr(
        builder._taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5((tmp_path / "archives/fox.zip").read_bytes()).hexdigest(),
    )
    splits = split_file(tmp_path)
    metadata = source_config if target == "config" else splits
    content = metadata.read_bytes()
    metadata.write_bytes(b"\xef\xbb\xbf" + content)
    output = tmp_path / f"bom-{target}"
    build_args(builder, source_config, tmp_path, output, splits=splits)
    manifest = json.loads(
        (output / "scoring/manifest.json").read_text(encoding="utf-8")
    )
    assert (
        manifest["build"]["source_config_sha256"]
        == hashlib.sha256(source_config.read_bytes()).hexdigest()
    )
    assert (
        manifest["build"]["splits_sha256"]
        == hashlib.sha256(splits.read_bytes()).hexdigest()
    )


@pytest.mark.parametrize("max_records", [0, -1, True, 1.5, "3"])
def test_record_limit_requires_positive_exact_integer(
    modules, source_config, tmp_path, max_records
):
    _, builder = modules
    with pytest.raises(ValueError, match="max_records"):
        build_args(
            builder,
            source_config,
            tmp_path,
            tmp_path / "bad-limit",
            max_records=max_records,
        )
    assert not (tmp_path / "bad-limit").exists()


def test_record_limit_exceeded_and_empty_window_leave_no_output(
    modules, source_config, tmp_path, monkeypatch
):
    _, builder = modules
    monkeypatch.setattr(
        builder._taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5((tmp_path / "archives/fox.zip").read_bytes()).hexdigest(),
    )
    too_small = tmp_path / "too-small"
    with pytest.raises(ValueError, match="record limit"):
        build_args(builder, source_config, tmp_path, too_small, max_records=2)
    assert not too_small.exists()
    empty = tmp_path / "empty-window"
    with pytest.raises(ValueError, match="selected no records"):
        build_args(
            builder,
            source_config,
            tmp_path,
            empty,
            time_from="2022-01-18T12:00:04Z",
            time_to="2022-01-18T12:00:05Z",
        )
    assert not empty.exists()


def test_public_manifests_expose_artifact_hashes_without_gold_or_proof_details(
    modules, source_config, tmp_path, monkeypatch
):
    _, builder = modules
    monkeypatch.setattr(
        builder._taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5((tmp_path / "archives/fox.zip").read_bytes()).hexdigest(),
    )
    output = tmp_path / "public-case"
    build_args(builder, source_config, tmp_path, output)
    agent_manifest = json.loads(
        (output / "agent/manifest.json").read_text(encoding="utf-8")
    )
    score_manifest = json.loads(
        (output / "scoring/manifest.json").read_text(encoding="utf-8")
    )
    assert set(score_manifest["artifacts"]) == {
        "agent/events.jsonl",
        "agent/manifest.json",
        "scoring/gold.jsonl",
        "scoring/source-gold.json",
    }
    input_paths = set(score_manifest["input_sha256"])
    assert str(source_config.resolve()) in input_paths
    assert str((tmp_path / "metadata/splits.json").resolve()) in input_paths
    config = json.loads(source_config.read_text(encoding="utf-8"))
    for entry in config["sources"]:
        assert str((source_config.parent / entry["events"]).resolve()) in input_paths
        assert (
            str((source_config.parent / entry["scored_gold"]).resolve()) in input_paths
        )
        assert str((source_config.parent / entry["proof"]).resolve()) in input_paths
        proof = json.loads(
            (source_config.parent / entry["proof"]).read_text(encoding="utf-8")
        )
        assert {item["path"] for item in proof["inputs"].values()} <= input_paths
    # The agent manifest has only the documented public keys.
    assert set(agent_manifest) == {
        "schema_version",
        "generator_version",
        "case_id",
        "dataset_id",
        "scenario",
        "split",
        "time_from",
        "time_to",
        "selection",
        "event_count",
        "events_file",
        "events_sha256",
        "sources",
    }
    assert "source_config" not in json.dumps(agent_manifest)
    assert agent_manifest["event_count"] == 3
    assert score_manifest["artifact_records"] == {
        "agent/events.jsonl": 3,
        "scoring/gold.jsonl": 3,
    }


def test_invalid_split_and_unaware_or_reversed_times_rejected_before_output(
    modules, source_config, tmp_path, monkeypatch
):
    _, builder = modules
    monkeypatch.setattr(
        builder._taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5((tmp_path / "archives/fox.zip").read_bytes()).hexdigest(),
    )
    bad_splits = split_file(tmp_path)
    data = json.loads(bad_splits.read_text(encoding="utf-8"))
    data["test"] = ["fox"]
    bad_splits.write_text(json.dumps(data), encoding="utf-8")
    assert json.loads(bad_splits.read_text(encoding="utf-8"))["test"] == ["fox"]
    with pytest.raises(ValueError, match="split configuration"):
        build_args(
            builder,
            source_config,
            tmp_path,
            tmp_path / "bad-split",
            splits=bad_splits,
        )
    assert not (tmp_path / "bad-split").exists()
    for start, end in (
        ("2022-01-18T12:00:01", "2022-01-18T12:00:04Z"),
        ("2022-01-18T12:00:04Z", "2022-01-18T12:00:01Z"),
    ):
        output = tmp_path / f"bad-time-{len(list(tmp_path.glob('bad-time-*')))}"
        with pytest.raises((TypeError, ValueError)):
            build_args(
                builder, source_config, tmp_path, output, time_from=start, time_to=end
            )
        assert not output.exists()


def test_protected_input_output_and_preexisting_destination_are_preserved(
    modules, source_config, tmp_path, monkeypatch
):
    _, builder = modules
    monkeypatch.setattr(
        builder._taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5((tmp_path / "archives/fox.zip").read_bytes()).hexdigest(),
    )
    existing = tmp_path / "already-there"
    existing.mkdir()
    sentinel = existing / "keep.txt"
    sentinel.write_text("preserve", encoding="utf-8")
    with pytest.raises(FileExistsError):
        build_args(builder, source_config, tmp_path, existing)
    assert sentinel.read_text(encoding="utf-8") == "preserve"
    protected = tmp_path / "raw"
    with pytest.raises(ValueError, match="protected input"):
        build_args(builder, source_config, tmp_path, protected)


def test_stale_proof_input_hash_is_rejected_before_output(
    modules, source_config, tmp_path, monkeypatch
):
    _, builder = modules
    monkeypatch.setattr(
        builder._taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5((tmp_path / "archives/fox.zip").read_bytes()).hexdigest(),
    )
    config = json.loads(source_config.read_text(encoding="utf-8"))
    proof_path = source_config.parent / config["sources"][0]["proof"]
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    raw_path = Path(proof["inputs"]["raw"]["path"])
    raw_path.write_bytes(raw_path.read_bytes() + b"mutated\n")
    output = tmp_path / "stale-input"
    with pytest.raises(ValueError, match="stale proof input hash"):
        build_args(builder, source_config, tmp_path, output)
    assert not output.exists()


def test_mutation_after_real_proof_load_is_rejected_before_output(
    modules, source_config, tmp_path, monkeypatch
):
    _, builder = modules
    monkeypatch.setattr(
        builder._taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5((tmp_path / "archives/fox.zip").read_bytes()).hexdigest(),
    )
    real_load = builder._taxonomy._load_proof
    changed = False

    def mutate_after_load(path, gold):
        nonlocal changed
        result = real_load(path, gold)
        if not changed:
            labels = result[1]["labels"]
            Path(labels).write_bytes(Path(labels).read_bytes() + b"\n")
            changed = True
        return result

    monkeypatch.setattr(builder._taxonomy, "_load_proof", mutate_after_load)
    output = tmp_path / "changed-during-load"
    with pytest.raises(ValueError, match="input changed during build"):
        build_args(builder, source_config, tmp_path, output)
    assert changed
    assert not output.exists()


@pytest.mark.parametrize("mutation", ["artifact_hash", "input_hash", "bool_count"])
def test_rebuild_rejects_tampered_manifest_without_output(
    modules, source_config, tmp_path, monkeypatch, mutation
):
    _, builder = modules
    monkeypatch.setattr(
        builder._taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5((tmp_path / "archives/fox.zip").read_bytes()).hexdigest(),
    )
    trusted = tmp_path / "trusted-case"
    build_args(builder, source_config, tmp_path, trusted)
    manifest = json.loads(
        (trusted / "scoring/manifest.json").read_text(encoding="utf-8")
    )
    if mutation == "artifact_hash":
        manifest["artifacts"]["agent/events.jsonl"] = "0" * 64
    elif mutation == "input_hash":
        first = next(iter(manifest["input_sha256"]))
        manifest["input_sha256"][first] = "0" * 64
    else:
        manifest["counts"]["selected"] = True
    tampered = source_config.parent / f"tampered-{mutation}.json"
    tampered.write_text(json.dumps(manifest), encoding="utf-8")
    output = tmp_path / f"rebuilt-{mutation}"
    with pytest.raises(ValueError, match="rebuild differs"):
        builder.rebuild_case(manifest=tampered, output_dir=output)
    assert not output.exists()


def test_nested_agent_ground_truth_rejected_with_real_updated_proof(
    modules, source_config, tmp_path, monkeypatch
):
    taxonomy, builder = modules
    archive = tmp_path / "archives/fox.zip"
    monkeypatch.setattr(
        taxonomy, "_OFFICIAL_MD5", hashlib.md5(archive.read_bytes()).hexdigest()
    )
    monkeypatch.setattr(
        builder._taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5(archive.read_bytes()).hexdigest(),
    )
    config = json.loads(source_config.read_text(encoding="utf-8"))
    entry = config["sources"][0]
    events = source_config.parent / entry["events"]
    event = json.loads(events.read_text(encoding="utf-8").splitlines()[0])
    event["untrusted_extra"] = {"labels": ["nested annotation"]}
    events.write_text(json.dumps(event, separators=(",", ":")) + "\n", encoding="utf-8")

    old_proof = source_config.parent / entry["proof"]
    proof = old_proof.parent / "nested-proof.json"
    original_gold = json.loads(old_proof.read_text(encoding="utf-8"))["inputs"]["gold"][
        "path"
    ]
    taxonomy.verify(
        dataset_root=tmp_path / "raw",
        events=events,
        gold=original_gold,
        join_report=tmp_path / "original-gold/join-0.json",
        archive=archive,
        time_from="2022-01-18T00:00:00Z",
        time_to="2022-01-19T00:00:00Z",
        output=proof,
    )
    scored = tmp_path / "scored/nested-scored.jsonl"
    taxonomy.map_gold(
        gold=original_gold,
        proof=proof,
        output=scored,
        report=tmp_path / "scored/nested-map.json",
    )
    entry["proof"] = Path(os.path.relpath(proof, source_config.parent)).as_posix()
    entry["scored_gold"] = Path(
        os.path.relpath(scored, source_config.parent)
    ).as_posix()
    source_config.write_text(json.dumps(config), encoding="utf-8")
    output = tmp_path / "nested-agent-gold"
    with pytest.raises(ValueError, match="structured gold fields"):
        build_args(builder, source_config, tmp_path, output)
    assert not output.exists()


@pytest.mark.parametrize("race", [False, True])
def test_exclusive_write_failure_cleans_owned_paths_and_preserves_racer(
    modules, source_config, tmp_path, monkeypatch, race
):
    _, builder = modules
    monkeypatch.setattr(
        builder._taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5((tmp_path / "archives/fox.zip").read_bytes()).hexdigest(),
    )
    output = tmp_path / "new-parent" / "nested" / "case"
    target = output / ("scoring/gold.jsonl" if race else "agent/events.jsonl")
    real_open = Path.open
    failed = False

    def fail_target(path, *args, **kwargs):
        nonlocal failed
        mode = kwargs.get("mode", args[0] if args else "r")
        if path == target and mode == "xb" and not failed:
            failed = True
            if race:
                with real_open(path, "wb") as stream:
                    stream.write(b"racing writer owns this file")
            raise OSError("injected exclusive create failure")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_target)
    with pytest.raises(OSError, match="injected exclusive create failure"):
        build_args(builder, source_config, tmp_path, output)
    if race:
        assert target.read_bytes() == b"racing writer owns this file"
        assert not (output / "agent/events.jsonl").exists()
        assert not (output / "agent/manifest.json").exists()
        assert not (output / "scoring/source-gold.json").exists()
    else:
        assert not output.exists()
        assert not output.parent.parent.exists()


@pytest.fixture
def subset_builder(modules, tmp_path, monkeypatch):
    _, builder = modules
    monkeypatch.setattr(
        builder._taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5((tmp_path / "archives/fox.zip").read_bytes()).hexdigest(),
    )
    return builder


def select_sources(source_config, indices, *, schema_version=2):
    config = json.loads(source_config.read_text(encoding="utf-8"))
    entries = config["sources"]
    config["schema_version"] = schema_version
    config["sources"] = [entries[ix] for ix in indices]
    source_config.write_text(json.dumps(config), encoding="utf-8")
    return entries


def assert_configured_inputs_only(manifest, source_config, entries, indices):
    configured = {LOGS[ix] for ix in indices}
    assert set(manifest["counts"]["per_source"]) == configured
    assert {row["relative_log_path"] for row in manifest["profiles"]} == configured
    expected_paths = {
        str(source_config.resolve()),
        str((source_config.parent / "splits.json").resolve()),
    }
    for ix in indices:
        entry = entries[ix]
        expected_paths.update(
            str((source_config.parent / entry[key]).resolve())
            for key in ("events", "scored_gold", "proof")
        )
        proof = json.loads(
            (source_config.parent / entry["proof"]).read_text(encoding="utf-8")
        )
        expected_paths.update(item["path"] for item in proof["inputs"].values())
    assert set(manifest["input_sha256"]) == expected_paths


def portable_sources(builder, source_config, data_root):
    config = json.loads(source_config.read_text(encoding="utf-8"))
    for entry in config["sources"]:
        path = (source_config.parent / entry["proof"]).resolve()
        proof = json.loads(path.read_text(encoding="utf-8"))
        value = builder._taxonomy.portable_proof(proof, data_root=data_root)
        path.write_text(json.dumps(value), encoding="utf-8")


def test_portable_case_identity_uses_only_observable_selection_metadata(
    modules, source_config
):
    _, builder = modules
    args = {
        "source_config": source_config,
        "time_from": "2022-01-18T12:00:01Z",
        "time_to": "2022-01-18T12:00:04Z",
    }
    first = builder.neutral_case_id(**args)
    assert first.startswith("ait-") and len(first) == 28
    config = json.loads(source_config.read_bytes())
    config["sources"].reverse()
    for entry in config["sources"]:
        entry["scored_gold"] = "answer-webshell-upload.jsonl"
        entry["proof"] = "answer-normal-proof.json"
    source_config.write_text(json.dumps(config), encoding="utf-8")
    assert builder.neutral_case_id(**args) == first
    assert (
        builder.neutral_case_id(**{**args, "time_to": "2022-01-18T12:00:05Z"}) != first
    )


def test_case_data_root_preserves_legacy_default_and_detects_portable_proofs(
    modules, source_config, tmp_path
):
    _, builder = modules
    args = {"source_config": source_config, "data_root": tmp_path}
    assert builder.case_data_root(**args) is None
    assert builder.case_data_root(**args, explicit=True) == tmp_path
    portable_sources(builder, source_config, tmp_path)
    assert builder.case_data_root(**args) == tmp_path


@pytest.mark.parametrize("bad_target", ["identity", "folder"])
def test_portable_case_rejects_answer_bearing_identity_and_output_folder(
    modules, source_config, tmp_path, monkeypatch, bad_target
):
    _, builder = modules
    monkeypatch.setattr(
        builder._taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5((tmp_path / "archives/fox.zip").read_bytes()).hexdigest(),
    )
    portable_sources(builder, source_config, tmp_path)
    case_id = builder.neutral_case_id(
        source_config=source_config,
        time_from="2022-01-18T12:00:01Z",
        time_to="2022-01-18T12:00:04Z",
    )
    output = tmp_path / (
        "fox-test-attack-webshell-upload" if bad_target == "folder" else case_id
    )
    with pytest.raises(ValueError, match="neutral case|case folder"):
        build_args(
            builder,
            source_config,
            tmp_path,
            output,
            data_root=tmp_path,
            case_id="fox-test-attack-webshell-upload"
            if bad_target == "identity"
            else case_id,
        )
    assert not output.exists()


def test_explicit_data_root_rebuilds_identically_after_original_inputs_are_removed(
    modules, source_config, tmp_path, monkeypatch
):
    _, builder = modules
    monkeypatch.setattr(
        builder._taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5((tmp_path / "archives/fox.zip").read_bytes()).hexdigest(),
    )
    splits = split_file(tmp_path)
    portable_sources(builder, source_config, tmp_path)
    case_id = builder.neutral_case_id(
        source_config=source_config,
        time_from="2022-01-18T12:00:01Z",
        time_to="2022-01-18T12:00:04Z",
    )
    output = tmp_path / case_id
    build_args(
        builder, source_config, tmp_path, output, data_root=tmp_path, case_id=case_id
    )
    manifest = json.loads((output / "scoring/manifest.json").read_bytes())
    assert manifest["build"]["path_base"] == "data_root"
    assert manifest["build"]["source_config"] == "metadata/sources.json"
    assert manifest["build"]["splits"] == "metadata/splits.json"
    assert all(
        not Path(path).is_absolute()
        and "\\" not in path
        and ".." not in Path(path).parts
        for path in manifest["input_sha256"]
    )
    relocated = tmp_path / "other-root"
    relocated.mkdir()
    for directory in list(tmp_path.iterdir()):
        if directory.is_dir() and directory not in (output, relocated):
            shutil.copytree(directory, relocated / directory.name)
            for original in directory.rglob("*"):
                if original.is_file():
                    original.write_bytes(b"original input unavailable\n")
    rebuilt = tmp_path / "reconstructed" / case_id
    builder.rebuild_case(
        manifest=output / "scoring/manifest.json",
        output_dir=rebuilt,
        data_root=relocated,
    )
    for relative in (
        "agent/events.jsonl",
        "agent/manifest.json",
        "scoring/gold.jsonl",
        "scoring/source-gold.json",
        "scoring/manifest.json",
    ):
        assert (output / relative).read_bytes() == (rebuilt / relative).read_bytes()
    assert splits.name == "splits.json"


@pytest.mark.parametrize(
    "reference",
    ["../outside.json", "/outside.json", "C:/outside.json", "metadata\\sources.json"],
)
def test_portable_rebuild_rejects_noncanonical_root_references(
    modules, source_config, tmp_path, monkeypatch, reference
):
    _, builder = modules
    monkeypatch.setattr(
        builder._taxonomy,
        "_OFFICIAL_MD5",
        hashlib.md5((tmp_path / "archives/fox.zip").read_bytes()).hexdigest(),
    )
    portable_sources(builder, source_config, tmp_path)
    case_id = builder.neutral_case_id(
        source_config=source_config,
        time_from="2022-01-18T12:00:01Z",
        time_to="2022-01-18T12:00:04Z",
    )
    output = tmp_path / case_id
    build_args(
        builder, source_config, tmp_path, output, data_root=tmp_path, case_id=case_id
    )
    manifest = json.loads((output / "scoring/manifest.json").read_bytes())
    original = manifest["build"]["source_config"]
    manifest["build"]["source_config"] = reference
    manifest["input_sha256"][reference] = manifest["input_sha256"].pop(original)
    tampered = tmp_path / "bad-reference.json"
    tampered.write_text(json.dumps(manifest), encoding="utf-8")
    dest = tmp_path / "rejected"
    with pytest.raises(ValueError, match="relative|reference"):
        builder.rebuild_case(manifest=tampered, output_dir=dest, data_root=tmp_path)
    assert not dest.exists()


@pytest.mark.parametrize("source_config", ["early_dns"], indirect=True)
def test_v2_dns_subset_opens_early_window_and_rebuilds_all_artifacts(
    source_config, subset_builder, tmp_path
):
    builder = subset_builder
    times = {
        "time_from": "2022-01-16T12:00:03Z",
        "time_to": "2022-01-16T12:00:04Z",
    }
    legacy = tmp_path / "legacy-early"
    with pytest.raises(ValueError, match="exceeds a complete source proof"):
        build_args(builder, source_config, tmp_path, legacy, **times)
    assert not legacy.exists()
    entries = select_sources(source_config, [2])
    # Omitted profiles are not dependencies, even when their files are absent.
    for entry in entries[:2]:
        for key in ("events", "scored_gold", "proof"):
            (source_config.parent / entry[key]).unlink()
    output = tmp_path / "dns-only"
    result = build_args(builder, source_config, tmp_path, output, **times)
    assert result["event_count"] == 1
    agent = json.loads((output / "agent/manifest.json").read_text(encoding="utf-8"))
    manifest = json.loads(
        (output / "scoring/manifest.json").read_text(encoding="utf-8")
    )
    assert agent["schema_version"] == manifest["schema_version"] == 2
    assert agent["generator_version"] == "ait-fox-agent-case-v2"
    assert manifest["generator_version"] == "ait-fox-development-case-v2"
    assert agent["sources"] == [LOGS[2]]
    assert_configured_inputs_only(manifest, source_config, entries, [2])
    event = json.loads((output / "agent/events.jsonl").read_text(encoding="utf-8"))
    gold = json.loads((output / "scoring/gold.jsonl").read_text(encoding="utf-8"))
    assert event["relative_log_path"] == LOGS[2]
    assert gold["is_attack"] is True
    assert gold["attack_types"] == ["data_exfiltration"]
    assert not {"labels", "rules", "is_attack", "attack_types", "source_gold"} & (
        event.keys() | agent.keys()
    )
    source_gold = json.loads(
        (output / "scoring/source-gold.json").read_text(encoding="utf-8")
    )
    assert source_gold["observed_source_ips"] == [
        {
            "value": "192.0.2.9",
            "role": "dns_query_client",
            "evidence_ids": [event["external_id"]],
        }
    ]
    assert source_gold["entry_candidates"] == []
    rebuilt = tmp_path / "dns-rebuilt"
    builder.rebuild_case(manifest=output / "scoring/manifest.json", output_dir=rebuilt)
    for relative in (
        "agent/events.jsonl",
        "agent/manifest.json",
        "scoring/gold.jsonl",
        "scoring/source-gold.json",
        "scoring/manifest.json",
    ):
        assert (output / relative).read_bytes() == (rebuilt / relative).read_bytes()


@pytest.mark.parametrize("indices", [(0,), (0, 2), (0, 1, 2)])
def test_v2_configured_profiles_include_zero_selected_without_omitted_inputs(
    source_config, subset_builder, tmp_path, indices
):
    entries = select_sources(source_config, indices)
    output = tmp_path / "configured-profiles"
    build_args(
        subset_builder,
        source_config,
        tmp_path,
        output,
        time_to="2022-01-18T12:00:02Z",
    )
    manifest = json.loads(
        (output / "scoring/manifest.json").read_text(encoding="utf-8")
    )
    assert_configured_inputs_only(manifest, source_config, entries, indices)
    assert manifest["counts"]["selected"] == 1
    for ix in indices:
        assert manifest["counts"]["per_source"][LOGS[ix]] == {
            "selected": int(ix == 0),
            "attack": int(ix == 0),
            "normal": 0,
            "unknown": 0,
        }


@pytest.mark.parametrize("version", [0, 3, True, 1.0, 2.0, "2", None])
def test_subset_config_rejects_unknown_or_inexact_version(
    modules, source_config, tmp_path, version
):
    _, builder = modules
    select_sources(source_config, [2], schema_version=version)
    output = tmp_path / "invalid-version"
    with pytest.raises(ValueError, match="source configuration"):
        build_args(builder, source_config, tmp_path, output)
    assert not output.exists()


@pytest.mark.parametrize("mutation", ["empty", "duplicate", "unknown", "legacy"])
def test_subset_config_rejects_invalid_source_selection(
    modules, source_config, tmp_path, mutation
):
    _, builder = modules
    select_sources(source_config, [2], schema_version=1 if mutation == "legacy" else 2)
    config = json.loads(source_config.read_text(encoding="utf-8"))
    if mutation == "empty":
        config["sources"] = []
    elif mutation == "duplicate":
        config["sources"] *= 2
    elif mutation == "unknown":
        config["sources"][0]["relative_log_path"] = "other/logs/dnsmasq.log"
    source_config.write_text(json.dumps(config), encoding="utf-8")
    output = tmp_path / "invalid-selection"
    with pytest.raises(ValueError):
        build_args(builder, source_config, tmp_path, output)
    assert not output.exists()


@pytest.mark.parametrize("source_config", ["early_dns"], indirect=True)
@pytest.mark.parametrize("mutation", ["mismatch", "stale", "out_of_scope"])
def test_v2_selected_proof_integrity_and_scope_remain_required(
    source_config, subset_builder, tmp_path, mutation
):
    entries = select_sources(source_config, [2])
    config = json.loads(source_config.read_text(encoding="utf-8"))
    proof_path = source_config.parent / entries[2]["proof"]
    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    expected_error = "exceeds a complete source proof"
    if mutation == "mismatch":
        config["sources"][0]["proof"] = entries[0]["proof"]
        source_config.write_text(json.dumps(config), encoding="utf-8")
        expected_error = "proof profile differs from source"
    elif mutation == "stale":
        raw = Path(proof["inputs"]["raw"]["path"])
        raw.write_bytes(raw.read_bytes() + b"changed\n")
        expected_error = "stale proof input hash"
    output = tmp_path / "invalid-selected-proof"
    with pytest.raises(ValueError, match=expected_error):
        build_args(
            subset_builder,
            source_config,
            tmp_path,
            output,
            time_from="2022-01-14T12:00:03Z"
            if mutation == "out_of_scope"
            else "2022-01-16T12:00:03Z",
            time_to="2022-01-16T12:00:04Z",
        )
    assert not output.exists()


def test_v2_verifies_complete_gold_for_configured_source_with_zero_selected_rows(
    source_config, subset_builder, tmp_path
):
    entries = select_sources(source_config, [0, 2])
    scored = source_config.parent / entries[2]["scored_gold"]
    row = json.loads(scored.read_text(encoding="utf-8"))
    row["attack_types"] = []
    scored.write_text(json.dumps(row) + "\n", encoding="utf-8")
    output = tmp_path / "bad-unselected-gold"
    with pytest.raises(ValueError, match="canonical complete mapping"):
        build_args(
            subset_builder,
            source_config,
            tmp_path,
            output,
            time_to="2022-01-18T12:00:02Z",
        )
    assert not output.exists()


@pytest.mark.parametrize(
    ("schema_version", "generator_version"),
    [
        (1, "ait-fox-development-case-v2"),
        (2, "ait-fox-development-case-v1"),
        (True, "ait-fox-development-case-v1"),
        (2.0, "ait-fox-development-case-v2"),
        (3, "ait-fox-development-case-v3"),
        (2, "unknown"),
        (1, "ait-fox-development-case-v1"),
    ],
)
def test_v2_rebuild_rejects_version_pair_tampering_and_cleans_output(
    source_config, subset_builder, tmp_path, schema_version, generator_version
):
    select_sources(source_config, [2])
    trusted = tmp_path / "trusted-v2"
    build_args(subset_builder, source_config, tmp_path, trusted)
    manifest = json.loads(
        (trusted / "scoring/manifest.json").read_text(encoding="utf-8")
    )
    manifest["schema_version"] = schema_version
    manifest["generator_version"] = generator_version
    tampered = source_config.parent / "version-tampered.json"
    tampered.write_text(json.dumps(manifest), encoding="utf-8")
    output = tmp_path / "version-rebuild"
    with pytest.raises(ValueError, match="manifest"):
        subset_builder.rebuild_case(manifest=tampered, output_dir=output)
    assert not output.exists()
