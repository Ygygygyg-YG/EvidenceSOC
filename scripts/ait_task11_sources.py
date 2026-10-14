"""Prepare the six fixed AIT Task 11 scenarios from verified no-PCAP archives.

All outputs are append-only. Existing outputs must agree with the current
official archive before they can be reused.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "evals" / "datasets" / "ait_v2"
WINDOWS = {
    "harrison": ("2022-02-04T00:00:00Z", "2022-02-09T00:00:00Z", "development"),
    "santos": ("2022-01-14T00:00:00Z", "2022-01-18T00:00:00Z", "development"),
    "wardbeck": ("2022-01-19T00:00:00Z", "2022-01-24T00:00:00Z", "validation"),
    "wheeler": ("2022-01-26T00:00:00Z", "2022-01-31T00:00:00Z", "development"),
    "shaw": ("2022-01-25T00:00:00Z", "2022-01-31T00:00:00Z", "test"),
    "wilson": ("2022-02-03T00:00:00Z", "2022-02-09T00:00:00Z", "test"),
}


def load(name: str):
    spec = importlib.util.spec_from_file_location(
        f"_task11_{name}", BASE / f"{name}.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def member_to_path(archive: zipfile.ZipFile, member: str, path: Path) -> None:
    matches = [item for item in archive.infolist() if item.filename == member]
    if len(matches) != 1 or matches[0].is_dir():
        raise ValueError(f"missing or ambiguous archive member: {member}")
    if path.exists():
        digest = hashlib.sha256()
        with archive.open(matches[0]) as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
        if sha256(path) != digest.hexdigest():
            raise ValueError(
                f"existing extracted member differs from archive: {member}"
            )
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with archive.open(matches[0]) as source, path.open("xb") as target:
            created = True
            for block in iter(lambda: source.read(1024 * 1024), b""):
                target.write(block)
    except BaseException:
        if created:
            path.unlink(missing_ok=True)
        raise


def report(path: Path, **required) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if any(value.get(key) != expected for key, expected in required.items()):
        raise ValueError(f"incomplete or unexpected processing result: {path}")
    return value


def prepare(name: str, *, taxonomy, apache, audit, dns, join) -> None:
    dataset_id = f"ait-v2.1:{name}"
    start, end, split = WINDOWS[name]
    archive_path = ROOT / "data" / "ait" / "downloads" / f"{name}_no-pcaps.zip"
    if taxonomy._hash(archive_path, "md5") != taxonomy._official_md5(dataset_id):
        raise ValueError(f"official MD5 mismatch: {name}")
    raw_root = ROOT / "data" / "ait" / "scenarios" / name / "raw"
    processed = raw_root.parent / "processed"
    apache_log = taxonomy._EXTENDED_APACHE_LOGS[name]
    sources = (
        ("apache", apache_log, apache.parse_apache_file),
        ("intranet-audit", taxonomy._AUDIT_LOG, audit.parse_audit_file),
        ("dnsmasq", taxonomy._DNS_LOG, dns.parse_dnsmasq_file),
    )
    with zipfile.ZipFile(archive_path) as bundle:
        member_to_path(bundle, "dataset.yaml", raw_root / "dataset.yaml")
        for _, log, _ in sources:
            for kind in ("gather", "labels"):
                member_to_path(bundle, f"{kind}/{log}", raw_root / kind / log)
    entries = []
    metadata = ROOT / "data" / "manifests"
    for stem, log, parse_file in sources:
        stem = f"{name}-{stem}"
        event = processed / "agent" / f"{stem}-events.jsonl"
        errors = processed / "reports" / f"{stem}-errors.jsonl"
        gold = processed / "gold" / f"{stem}-gold.jsonl"
        join_path = processed / "reports" / f"{stem}-join.json"
        proof = processed / "reports" / f"{stem}-completeness.json"
        scored = processed / "gold" / f"{stem}-scored-gold.jsonl"
        map_path = processed / "reports" / f"{stem}-taxonomy.json"
        print(f"{name}/{log}: parse", flush=True)
        if not event.exists() and not errors.exists():
            kwargs = {
                "dataset_root": raw_root,
                "dataset_id": dataset_id,
                "relative_log_path": log,
                "output": event,
                "errors": errors,
            }
            if log == taxonomy._DNS_LOG:
                kwargs.update(year=2022, utc_offset="+00:00")
            result = parse_file(**kwargs)
            if result.get("parse_errors") != 0 or result.get("truncated"):
                raise ValueError(f"incomplete parse: {name}/{log}")
        elif not event.exists() or not errors.exists():
            raise ValueError(f"partial parse outputs: {name}/{log}")
        if not gold.exists() and not join_path.exists():
            result = join.join_labels(
                dataset_root=raw_root,
                dataset_id=dataset_id,
                relative_log_path=log,
                events=event,
                output=gold,
                report=join_path,
            )
            if result.get("unmatched_annotation_lines") or result.get("truncated"):
                raise ValueError(f"incomplete label join: {name}/{log}")
        elif not gold.exists() or not join_path.exists():
            raise ValueError(f"partial join outputs: {name}/{log}")
        report(
            join_path,
            truncated=False,
            labels_complete_read=True,
            label_bounds_verified=True,
            unmatched_annotation_lines=0,
        )
        print(f"{name}/{log}: verify", flush=True)
        if not proof.exists():
            taxonomy.verify(
                dataset_root=raw_root,
                events=event,
                gold=gold,
                join_report=join_path,
                archive=archive_path,
                time_from=start,
                time_to=end,
                output=proof,
            )
        print(f"{name}/{log}: taxonomy", flush=True)
        if not scored.exists() and not map_path.exists():
            taxonomy.map_gold(gold=gold, proof=proof, output=scored, report=map_path)
        elif not scored.exists() or not map_path.exists():
            raise ValueError(f"partial taxonomy outputs: {name}/{log}")
        mapped = report(map_path, truncated=False, unknown_events=0)
        joined = report(join_path)
        if mapped["read_events"] != joined["read_events"]:
            raise ValueError(f"taxonomy row count differs from join: {name}/{log}")
        entries.append(
            {
                "relative_log_path": log,
                "events": event.relative_to(metadata.parent).as_posix(),
                "scored_gold": scored.relative_to(metadata.parent).as_posix(),
                "proof": proof.relative_to(metadata.parent).as_posix(),
            }
        )
        print(
            f"{name}/{log}: {mapped['read_events']} events, "
            f"{mapped['attack_events']} attack, {mapped['normal_events']} normal",
            flush=True,
        )
    config = metadata / f"{name}-{split}-sources.json"
    value = {
        "schema_version": 2,
        "dataset_id": dataset_id,
        "scenario": name,
        "split": split,
        "sources": entries,
    }
    # Paths in the source config are relative to data/manifests, not data/.
    for entry in entries:
        for key in ("events", "scored_gold", "proof"):
            entry[key] = "../" + entry[key]
    if config.exists():
        if json.loads(config.read_text(encoding="utf-8")) != value:
            raise ValueError(f"existing source config differs: {config}")
    else:
        config.parent.mkdir(parents=True, exist_ok=True)
        with config.open("x", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    print(f"{name}: source config ready", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenarios", nargs="*", choices=WINDOWS, default=list(WINDOWS))
    args = parser.parse_args()
    modules = {
        "taxonomy": load("taxonomy"),
        "apache": load("parse"),
        "audit": load("audit_parse"),
        "dns": load("dnsmasq_parse"),
        "join": load("join_labels"),
    }
    for name in args.scenarios:
        prepare(name, **modules)


if __name__ == "__main__":
    main()
