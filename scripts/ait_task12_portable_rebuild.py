"""Copy verified AIT inputs, freeze portable packs, and reconstruct in another root.

No model or investigation runs are performed. The source manifest binds the
archive and six proof inputs, scored gold, portable proofs and source configs.
Acquisition logs keep legacy provenance outside the deterministic input ledger.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = {
    "harrison": "development",
    "santos": "development",
    "wheeler": "development",
    "wardbeck": "validation",
    "shaw": "test",
    "wilson": "test",
}
ARTIFACTS = (
    "agent/manifest.json",
    "agent/events.jsonl",
    "scoring/manifest.json",
    "scoring/gold.jsonl",
    "scoring/source-gold.json",
)
INPUT_MANIFEST = "manifests/ait-task12-portable-inputs.json"


def load_builder():
    path = ROOT / "evals/datasets/ait_v2/build_manifests.py"
    spec = importlib.util.spec_from_file_location("_task12_portable_builder", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def write_new(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != data:
            raise ValueError(f"existing output differs: {path}")
        return
    with path.open("xb") as stream:
        stream.write(data)


def copy_verified_file(source, destination, expected):
    source, destination = Path(source), Path(destination)
    builder = load_builder()
    for path in (source, destination):
        builder._parser._reject_path_links(path)
    if sha256(source) != expected:
        raise ValueError(f"source hash differs: {source}")
    if destination.exists():
        if sha256(destination) != expected:
            raise ValueError(f"destination hash differs: {destination}")
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with source.open("rb") as origin, destination.open("xb") as target:
            created = True
            shutil.copyfileobj(origin, target, 1024 * 1024)
        if sha256(destination) != expected or sha256(source) != expected:
            raise ValueError(f"copy hash differs: {destination}")
    except BaseException:
        if created:
            destination.unlink(missing_ok=True)
        raise


def verify_inputs(value, data_root):
    builder = load_builder()
    if value.get("schema_version") != 1 or value.get("path_base") != "data_root":
        raise ValueError("invalid portable source manifest")
    for reference, expected in value["files"].items():
        path = builder._taxonomy._resolve_reference(reference, data_root)
        if (
            sha256(path) != expected["sha256"]
            or path.stat().st_size != expected["bytes"]
        ):
            raise ValueError(f"input hash or size differs: {reference}")
    print(f"verified {len(value['files'])} portable source files", flush=True)


def acquire(*, source_data_root, data_root, report):
    builder = load_builder()
    taxonomy = builder._taxonomy
    source_root = taxonomy._data_root(source_data_root)
    Path(data_root).mkdir(parents=True, exist_ok=True)
    target_root = taxonomy._data_root(data_root)
    if (
        source_root == target_root
        or source_root.is_relative_to(target_root)
        or target_root.is_relative_to(source_root)
    ):
        raise ValueError("source and destination data roots must be separate")
    files, provenance, profiles, metadata_migration = {}, [], [], []

    def copied(path, expected=None):
        reference = taxonomy._relative_reference(path, source_root)
        digest = expected or sha256(path)
        destination = taxonomy._resolve_reference(reference, target_root)
        copy_verified_file(path, destination, digest)
        files[reference] = {"sha256": digest, "bytes": destination.stat().st_size}
        print(f"COPY SHA256 {digest} {reference}", flush=True)

    def metadata(path):
        reference = taxonomy._relative_reference(path, source_root)
        destination = taxonomy._resolve_reference(reference, target_root)
        value = read_json(path)
        data = json_bytes(value)
        if destination.exists():
            if read_json(destination) != value:
                raise ValueError(f"destination metadata differs: {reference}")
            destination.write_bytes(data)
        else:
            write_new(destination, data)
        files[reference] = {"sha256": sha256(destination), "bytes": len(data)}
        metadata_migration.append(
            {
                "path": reference,
                "old_sha256": sha256(path),
                "new_sha256": sha256(destination),
                "reason": "canonical UTF-8 LF serialization",
            }
        )
        print(f"METADATA SHA256 {sha256(destination)} {reference}", flush=True)

    for scenario, split in SCENARIOS.items():
        config_path = source_root / "manifests" / f"{scenario}-{split}-sources.json"
        config = read_json(config_path)
        for entry in config["sources"]:
            proof_path = (config_path.parent / entry["proof"]).resolve()
            captured = read_json(proof_path)
            portable = captured.get("schema_version") == 2
            gold_path = (
                taxonomy._resolve_reference(
                    captured["inputs"]["gold"]["path"], source_root
                )
                if portable
                else Path(captured["inputs"]["gold"]["path"])
            )
            proof, inputs, _ = taxonomy._load_proof(
                proof_path, gold_path, data_root=source_root if portable else None
            )
            for name, path in inputs.items():
                copied(path, proof["inputs"][name]["sha256"])
            copied((config_path.parent / entry["scored_gold"]).resolve())
            normalized = (
                proof
                if portable
                else taxonomy.portable_proof(proof, data_root=source_root)
            )
            reference = taxonomy._relative_reference(proof_path, source_root)
            destination = taxonomy._resolve_reference(reference, target_root)
            write_new(
                destination,
                proof_path.read_bytes() if portable else json_bytes(normalized),
            )
            files[reference] = {
                "sha256": sha256(destination),
                "bytes": destination.stat().st_size,
            }
            profiles.append(
                {
                    "dataset_id": proof["dataset_id"],
                    "relative_log_path": proof["relative_log_path"],
                    "proof": reference,
                    "archive_md5": proof["archive_md5"],
                    "complete": proof["complete"],
                    "counts": proof["counts"],
                }
            )
            provenance.append(
                {
                    "proof": reference,
                    "old_sha256": sha256(proof_path),
                    "new_sha256": sha256(destination),
                    "old_generated_at": proof.get("generated_at"),
                    "reason": "proof v2 binds all six inputs to data_root and excludes machine paths and wall-clock generation time",
                }
            )
        for config in sorted(
            (source_root / "manifests").glob(f"{scenario}-{split}*-sources.json")
        ):
            metadata(config)
    metadata(source_root / "manifests/ait-v2-splits.json")
    for filename in (
        "ait-task11-test-selection.json",
        "ait-task11-dev-validation-selection.json",
    ):
        metadata(source_root / "manifests" / filename)
    # Selections evolve when packs are frozen; they are separately hash-bound.
    for filename in (
        "ait-task11-test-selection.json",
        "ait-task11-dev-validation-selection.json",
    ):
        files.pop("manifests/" + filename)
    value = {
        "schema_version": 1,
        "path_base": "data_root",
        "scenarios": SCENARIOS,
        "files": dict(sorted(files.items())),
        "profiles": profiles,
    }
    input_path = target_root / INPUT_MANIFEST
    write_new(input_path, json_bytes(value))
    verify_inputs(value, target_root)
    write_new(
        report,
        json_bytes(
            {
                "source_data_root": str(source_root),
                "data_root": str(target_root),
                "input_manifest_sha256": sha256(input_path),
                "file_count": len(files),
                "copied_bytes": sum(row["bytes"] for row in files.values()),
                "proof_migration": provenance,
                "metadata_migration": metadata_migration,
                "inputs": value,
            }
        ),
    )


def configuration(root, row):
    scenario, split = row["scenario"], row.get("split", "test")
    if scenario not in SCENARIOS or split != SCENARIOS[scenario]:
        raise ValueError("selection scenario or split is invalid")
    if split == "test":
        profiles = row["profiles"]
        if (
            not profiles
            or len(set(profiles)) != len(profiles)
            or not set(profiles) <= {"apache", "intranet-audit", "dnsmasq"}
        ):
            raise ValueError("selection source profiles are invalid")
        suffix = "" if len(profiles) == 3 else "-" + profiles[0]
    else:
        suffix = "-audit" if row["class"] == "normal" else ""
    return load_builder()._taxonomy._resolve_reference(
        f"manifests/{scenario}-{split}{suffix}-sources.json", root
    )


def selection_identity(row, value, *, neutral):
    split = row.get("split", value.get("split", "test"))
    pattern = r"ait-[0-9a-f]{24}" if neutral else r"[a-z0-9][a-z0-9_-]{0,63}"
    case_id = row.get("case_id")
    if (
        split not in {"development", "validation", "test"}
        or not isinstance(case_id, str)
        or not re.fullmatch(pattern, case_id)
    ):
        raise ValueError("selection split or case identity is invalid")
    return split, case_id


def freeze(*, data_root, selection, report, legacy_cases_root=None):
    builder = load_builder()
    root = builder._taxonomy._data_root(data_root)
    verify_inputs(read_json(root / INPUT_MANIFEST), root)
    path = builder._taxonomy._resolve_reference(selection, root)
    value = read_json(path)
    old_hash = sha256(path)
    backup = (
        root.parent
        / ".backups/ait-portability"
        / (path.name + "." + old_hash + ".json")
    )
    write_new(backup, path.read_bytes())
    relations, identities = [], {}
    for row in value["cases"]:
        split, _ = selection_identity(row, value, neutral=False)
        old_id = row.get("legacy_case_id", row["case_id"])
        selection_identity({"case_id": old_id, "split": split}, value, neutral=False)
        config = configuration(root, row)
        case_id = builder.neutral_case_id(
            source_config=config,
            time_from=row["time_from"],
            time_to=row["time_to"],
        )
        identities[row["case_id"]] = case_id
        output = builder._taxonomy._resolve_reference(
            f"ait/cases/{split}/{case_id}", root
        )
        result = builder.build_case(
            source_config=config,
            splits=root / "manifests/ait-v2-splits.json",
            case_id=case_id,
            time_from=row["time_from"],
            time_to=row["time_to"],
            output_dir=output,
            data_root=root,
        )
        expected = row.get("actual_count", row.get("counts"))
        if any(result["counts"][key] != count for key, count in expected.items()):
            raise ValueError(f"selected counts changed: {row['case_id']}")
        relation = {
            "case_id": case_id,
            "legacy_case_id": old_id,
            "old_scoring_manifest_sha256": row["scoring_manifest_sha256"],
            "new_scoring_manifest_sha256": sha256(output / "scoring/manifest.json"),
        }
        if legacy_cases_root is not None:
            old = builder._taxonomy._resolve_reference(
                f"{split}/{old_id}", legacy_cases_root
            )
            relation["artifacts"] = {}
            for artifact in ARTIFACTS:
                old_digest, new_digest = (
                    sha256(old / artifact),
                    sha256(output / artifact),
                )
                relation["artifacts"][artifact] = {
                    "old_sha256": old_digest,
                    "new_sha256": new_digest,
                }
                if artifact == "agent/manifest.json":
                    expected_agent = read_json(old / artifact)
                    expected_agent["case_id"] = case_id
                    if expected_agent != read_json(output / artifact):
                        raise ValueError(
                            f"Agent metadata changed beyond identity: {old_id}"
                        )
                elif artifact != "scoring/manifest.json" and old_digest != new_digest:
                    raise ValueError(
                        f"path migration changed event/answer content: {row['case_id']}/{artifact}"
                    )
        row["legacy_case_id"] = old_id
        row["case_id"] = case_id
        row["scoring_manifest_sha256"] = relation["new_scoring_manifest_sha256"]
        if "agent_manifest_sha256" in row:
            row["agent_manifest_sha256"] = sha256(output / "agent/manifest.json")
        row["rebuild_verified"] = True
        relations.append(relation)
        print(
            f"FREEZE {row['case_id']} {relation['new_scoring_manifest_sha256']}",
            flush=True,
        )
    if "ablation_case_ids" in value:
        value["ablation_case_ids"] = [
            identities[name] for name in value["ablation_case_ids"]
        ]
    value["case_identity"] = (
        "sha256 of dataset/scenario/split/window/source paths/max_records; labels and legacy IDs excluded"
    )
    path.write_bytes(json_bytes(value))
    write_new(
        report,
        json_bytes(
            {
                "data_root": str(root),
                "selection": selection,
                "old_selection_sha256": old_hash,
                "new_selection_sha256": sha256(path),
                "backup": str(backup),
                "reason": "stable data_root references replace absolute scoring paths and deterministic neutral IDs replace answer-bearing legacy IDs; windows, events and gold bytes are unchanged",
                "cases": relations,
            }
        ),
    )


def rebuild(*, data_root, frozen_root, selection, report):
    builder = load_builder()
    root = builder._taxonomy._data_root(data_root)
    frozen = builder._taxonomy._data_root(frozen_root)
    verify_inputs(read_json(frozen / INPUT_MANIFEST), root)
    selection_path = builder._taxonomy._resolve_reference(selection, frozen)
    value = read_json(selection_path)
    reconstructed = json.loads(json.dumps(value))
    comparisons = []
    for row in reconstructed["cases"]:
        split, case_id = selection_identity(row, value, neutral=True)
        canonical = builder._taxonomy._resolve_reference(
            f"ait/cases/{split}/{case_id}", frozen
        )
        destination = builder._taxonomy._resolve_reference(
            f"ait/rebuilds/{split}/{case_id}", root
        )
        manifest = canonical / "scoring/manifest.json"
        if sha256(manifest) != row["scoring_manifest_sha256"]:
            raise ValueError(f"frozen scoring manifest hash differs: {row['case_id']}")
        builder.rebuild_case(manifest=manifest, output_dir=destination, data_root=root)
        artifacts = {}
        for artifact in ARTIFACTS:
            current, relocated = (
                sha256(canonical / artifact),
                sha256(destination / artifact),
            )
            if current != relocated:
                raise ValueError(
                    f"cross-root artifact differs: {row['case_id']}/{artifact}"
                )
            artifacts[artifact] = {
                "current_sha256": current,
                "relocated_sha256": relocated,
            }
        comparisons.append({"case_id": row["case_id"], "artifacts": artifacts})
        row["scoring_manifest_sha256"] = sha256(destination / "scoring/manifest.json")
        if "agent_manifest_sha256" in row:
            row["agent_manifest_sha256"] = sha256(destination / "agent/manifest.json")
        row["rebuild_verified"] = True
        print(f"REBUILD IDENTICAL {row['case_id']}", flush=True)
    relocated_selection = builder._taxonomy._resolve_reference(selection, root)
    if json_bytes(reconstructed) != selection_path.read_bytes():
        raise ValueError("reconstructed selection differs from frozen selection")
    write_new(relocated_selection, json_bytes(reconstructed))
    write_new(
        report,
        json_bytes(
            {
                "data_root": str(root),
                "frozen_root": str(frozen),
                "selection_sha256": sha256(selection_path),
                "relocated_selection_sha256": sha256(relocated_selection),
                "selection_identical": True,
                "case_count": len(comparisons),
                "all_artifacts_identical": True,
                "cases": comparisons,
            }
        ),
    )


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    commands = cli.add_subparsers(dest="command", required=True)
    acquire_cli = commands.add_parser("acquire")
    acquire_cli.add_argument("--source-data-root", required=True)
    freeze_cli = commands.add_parser("freeze")
    freeze_cli.add_argument("--legacy-cases-root")
    rebuild_cli = commands.add_parser("rebuild")
    rebuild_cli.add_argument("--frozen-root", required=True)
    for command in (acquire_cli, freeze_cli, rebuild_cli):
        command.add_argument("--data-root", required=True)
        command.add_argument("--report", required=True)
    for command in (freeze_cli, rebuild_cli):
        command.add_argument(
            "--selection", default="manifests/ait-task11-test-selection.json"
        )
    args = vars(cli.parse_args())
    command = args.pop("command")
    {"acquire": acquire, "freeze": freeze, "rebuild": rebuild}[command](**args)


if __name__ == "__main__":
    main()
