"""Model worker bootstrap and controller Docker boundary, with a pre-call handshake.

The bootstrap probes and invokes the adapter in one Python process. No repository,
labels, docs or sibling cases are mounted. Importing this module never starts Docker.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import uuid
import zipfile
from hashlib import sha256
from pathlib import Path

from evals.adapters.worker_errors import WorkerInfrastructureError, WorkerTransportError

PROBE_PREFIX = "TASK13_WORKER_PROBE:"
READ_ONLY_MOUNTS = {
    "/app/agent",
    "/app/source",
    "/app/spec.json",
    "/app/runtime.py",
    "/opt/task13-deps",
    "/app/knowledge",
}
WRITABLE_MOUNTS = {"/app/budget", "/app/output"}
E_PLANNING_SCHEMA = "task13-e-planning-worker-v1"
E_PLANNING_REVIEW_SCHEMA = "task13-e-planning-review-worker-v1"
EPOCH_REGRESSION_SCHEMA = "task13-remediation-worker-v3"
EXPORT_PATHS = [
    "services/backend/src",
    "evals/contracts.py",
    "evals/e_planning.py",
    "evals/adapters",
    "scripts/dedale_task12_runtime.py",
    "scripts/task13_worker_runtime.py",
]


def dependency_tree_hash(root: Path) -> str:
    import hashlib

    root = Path(root)
    digest = sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or path.is_junction():
            raise ValueError("runtime resources contain a filesystem link")
        if path.is_file() and path != root / "task13_dependencies.json":
            digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\0")
            with path.open("rb") as stream:
                digest.update(hashlib.file_digest(stream, "sha256").digest())
    return digest.hexdigest()


def dependency_commands(
    *, repository: Path, destination: Path, python_version: str
) -> list[list[str]]:
    if not re.fullmatch(r"3\.(?:12|13|14)\.\d+", python_version):
        raise ValueError("dependency target needs an explicit supported Python ABI")
    requirements = Path(destination) / "requirements.lock.txt"
    return [
        [
            "uv",
            "export",
            "--project",
            str(Path(repository) / "services/backend"),
            "--locked",
            "--no-dev",
            "--no-emit-project",
            "--format",
            "requirements.txt",
            "--output-file",
            str(requirements),
        ],
        [
            "uv",
            "pip",
            "install",
            "--python-platform",
            "x86_64-manylinux_2_28",
            "--python-version",
            python_version,
            "--only-binary",
            ":all:",
            "--require-hashes",
            "--no-deps",
            "--target",
            str(destination),
            "--requirements",
            str(requirements),
        ],
    ]


def prepare_dependencies(
    *, repository: Path, destination: Path, python_version: str
) -> dict:
    from evals.runners.manifest import file_hash, write_immutable_json

    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    environment = {**os.environ, "UV_CACHE_DIR": str(Path(repository) / ".uv-cache")}
    lock_hash = file_hash(Path(repository) / "services/backend/uv.lock")
    commands = dependency_commands(
        repository=repository, destination=destination, python_version=python_version
    )
    for command in commands:
        subprocess.run(
            command,
            cwd=repository,
            env=environment,
            check=True,
            stdout=subprocess.DEVNULL if command[1] == "export" else None,
        )
    if file_hash(Path(repository) / "services/backend/uv.lock") != lock_hash:
        raise ValueError("dependency preparation changed the frozen lock")
    receipt = {
        "platform": "linux-amd64",
        "python_version": python_version,
        "lock_sha256": lock_hash,
        "requirements_sha256": file_hash(destination / "requirements.lock.txt"),
        "tree_sha256": dependency_tree_hash(destination),
        "commands": commands,
    }
    write_immutable_json(destination / "task13_dependencies.json", receipt)
    return receipt


def docker_run_arguments(
    *,
    name: str,
    image_id: str,
    network: str,
    mounts: dict[str, str],
    environment: dict[str, str],
    schema_version: str | None = None,
) -> list[str]:
    readonly, writable = mount_policy(schema_version)
    if (
        not re.fullmatch(r"task13-worker-[a-z0-9]+", name)
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id)
        or not network
        or network in {"host", "none"}
        or not readonly.issubset(mounts)
        or set(mounts) - readonly - writable
        or (
            schema_version in {E_PLANNING_SCHEMA, E_PLANNING_REVIEW_SCHEMA}
            and not writable.issubset(mounts)
        )
    ):
        raise ValueError("unexpected Task13 Docker isolation boundary")
    args = [
        "run",
        "--rm",
        "--pull=never",
        "-i",
        "--name",
        name,
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=256m",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        "2g",
        "--cpus",
        "2",
        "--network",
        network,
        "--workdir",
        "/app/agent",
    ]
    for target, source in sorted(mounts.items()):
        if "," in source or not source:
            raise ValueError("invalid Docker bind source")
        mode = "" if target in writable else ",readonly"
        args += ["--mount", f"type=bind,source={source},target={target}{mode}"]
    for key in sorted(environment):
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise ValueError("invalid explicit environment key")
        args += ["--env", key]
    return args + ["--entrypoint", "python3", image_id, "-B", "/app/runtime.py"]


def mount_policy(schema_version: str | None = None) -> tuple[set, set]:
    if schema_version in {E_PLANNING_SCHEMA, E_PLANNING_REVIEW_SCHEMA}:
        return READ_ONLY_MOUNTS | {"/app/import-source"}, WRITABLE_MOUNTS | {
            "/app/import-dispatch"
        }
    return READ_ONLY_MOUNTS, WRITABLE_MOUNTS


def e_planning_runtime_binding(options: dict, dependency_receipt: dict) -> dict:
    """Derive the actual host runtime identity, independently of worker claims."""
    from evals.runners.manifest import file_hash

    if dependency_receipt.get("lock_sha256") != options["dependencies_lock_sha256"]:
        raise ValueError("planning dependency receipt differs from runtime")
    return {
        "image_id": options["image_id"],
        "dependencies_lock_sha256": options["dependencies_lock_sha256"],
        "dependencies_tree_sha256": dependency_receipt["tree_sha256"],
        "knowledge_sha256": options["knowledge_sha256"],
        "controller_manifest_sha256": file_hash(
            Path(options["controller_manifest_path"])
        ),
    }


def validate_e_planning_probe(probe: dict, request, *, authority_sha256: str) -> None:
    from evals.contracts import canonical_hash

    expected = {
        "source_package_manifest_sha256": request.source_package_manifest_sha256,
        "registration_sha256": request.registration_sha256,
        "request_sha256": canonical_hash(request),
        "authority_sha256": authority_sha256,
        "readonly_source": True,
        "writable_dispatch": True,
    }
    if any(
        type(probe.get(k)) is not type(v) or probe[k] != v for k, v in expected.items()
    ):
        raise ValueError("planning pre-GO source, journal or mount probe differs")


def _planning_journal_path(path: Path) -> Path:
    path = Path(path)
    if path.name != "e-planning.sqlite" or not path.is_file():
        raise ValueError(
            "planning requires its existing uniquely named dispatch journal"
        )
    allowed = {path.name + suffix for suffix in ("", "-wal", "-shm", "-journal")}
    for entry in (path.parent, *path.parent.parents, *path.parent.iterdir()):
        if entry.is_symlink() or entry.is_junction():
            raise ValueError("planning journal cannot contain filesystem links")
    for entry in path.parent.iterdir():
        if (
            not entry.is_file()
            or entry.name not in allowed
            or entry.stat().st_nlink != 1
        ):
            raise ValueError("planning dispatch mount contains unregistered files")
    return path.resolve()


def _validate_planning_source(request, imported) -> None:
    if imported.source_identity != request.source_identity:
        raise ValueError("planning original source identity differs")
    provenance = imported.provenance
    expected = request.source.model_dump(mode="json")
    expected.pop("source_identity")
    if any(provenance.get(key) != value for key, value in expected.items()):
        raise ValueError("planning portable package original provenance differs")


def validate_e_planning_host(
    request, agent_dir: Path, options: dict, dependency_receipt: dict, *, review=False
) -> dict:
    """Read-only admission checks run before creating a container or passing a key."""
    from evals.adapters.analysis_package import verify_portable_analysis_package
    from evals.adapters.e_planning_journal import EPlanningDispatchJournal
    from evals.adapters.remediation_worker import (
        require_existing_budget,
        validate_exported_source,
    )
    from evals.adapters.source_epochs import require_registered_epoch
    from evals.runners.manifest import file_hash

    if (
        options["phase"] != ("verification" if review else "development")
        or options.get("budget_identity") != request.budget_identity
    ):
        raise ValueError("planning phase or original budget identity differs")
    validate_exported_source(
        request,
        agent_dir,
        Path(options["source_dir"]),
        source_commit=options["source_commit"],
    )
    budget_path = Path(options["budget_dir"]) / "campaign.sqlite"
    require_existing_budget(budget_path, request.budget_identity)
    epoch = require_registered_epoch(
        budget_path,
        request.epoch_id,
        source_sha256=request.source_sha256,
        config_sha256=request.config_sha256,
        budget_identity=request.budget_identity,
        manifest_sha256=request.epoch_manifest_sha256,
        latest=True,
    )
    actual_runtime = e_planning_runtime_binding(options, dependency_receipt)
    if (
        epoch["source_commit"] != request.source_commit
        or Path(epoch["budget_path"]).resolve() != budget_path.resolve()
        or epoch["runtime_binding"] != actual_runtime
    ):
        raise ValueError("planning registered source epoch runtime differs")
    root = Path(__file__).resolve().parents[1]
    required_entries = {
        "scripts/task13_worker_runtime.py",
        "evals/adapters/e_planning_worker.py",
        "evals/adapters/e_planning_contracts.py",
        "evals/adapters/e_planning_journal.py",
        "evals/adapters/analysis_package.py",
        "evals/adapters/analysis_import.py",
        "evals/e_planning.py",
        "evals/adapters/e_planning_review.py",
        "evals/adapters/verification_worker.py",
    }
    if not required_entries.issubset(epoch["entrypoints"]) or any(
        file_hash(root / relative) != digest
        for relative, digest in epoch["entrypoints"].items()
    ):
        raise ValueError(
            "planning actual controller entrypoints differ from source epoch"
        )
    imported = verify_portable_analysis_package(
        Path(options["import_source_dir"]), request.source_package_manifest_sha256
    )
    _validate_planning_source(request, imported)
    journal_path = _planning_journal_path(Path(options["import_dispatch_path"]))
    journal = EPlanningDispatchJournal.open_existing(
        journal_path,
        expected_registration_sha256=request.registration_sha256,
        expected_authority_sha256=options["planning_authority_sha256"],
    )
    journal.validate_request(request)
    return actual_runtime


def e_planning_worker_probe(request) -> dict:
    """Inspect actual read-only source and existing metadata journal before GO."""
    from evals.adapters.analysis_package import verify_portable_analysis_package
    from evals.adapters.e_planning_journal import EPlanningDispatchJournal
    from evals.contracts import canonical_hash

    source = Path(os.environ["TASK13_IMPORT_SOURCE_DIR"])
    imported = verify_portable_analysis_package(
        source, request.source_package_manifest_sha256
    )
    _validate_planning_source(request, imported)
    journal_path = _planning_journal_path(Path(os.environ["TASK13_IMPORT_DISPATCH_DB"]))
    authority_sha256 = os.environ["TASK13_IMPORT_AUTHORITY_SHA256"]
    journal = EPlanningDispatchJournal.open_existing(
        journal_path,
        expected_registration_sha256=request.registration_sha256,
        expected_authority_sha256=authority_sha256,
        mounted_host_journal_path=os.environ["TASK13_IMPORT_HOST_JOURNAL_PATH"],
    )
    journal.validate_request(request)
    flags = {}
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[4] in {
            "/app/import-source",
            "/app/import-dispatch",
        }:
            flags[fields[4]] = fields[5].split(",")
    probe = {
        "source_package_manifest_sha256": request.source_package_manifest_sha256,
        "registration_sha256": request.registration_sha256,
        "request_sha256": canonical_hash(request),
        "authority_sha256": authority_sha256,
        "readonly_source": "ro" in flags.get("/app/import-source", []),
        "writable_dispatch": "rw" in flags.get("/app/import-dispatch", []),
    }
    validate_e_planning_probe(probe, request, authority_sha256=authority_sha256)
    return probe


def worker_probe(
    agent_events: Path, forbidden: dict[str, list[Path]], nonce: str
) -> dict:
    if (
        set(forbidden) != {"scoring", "git", "other_case"}
        or not nonce
        or any(not values for values in forbidden.values())
    ):
        raise ValueError("isolation requires all canary boundary probes")
    payload = Path(agent_events).read_bytes()
    boundaries = {}
    for kind, paths in forbidden.items():
        records = []
        for path in paths:
            try:
                Path(path).read_bytes()
            except (FileNotFoundError, PermissionError, IsADirectoryError) as error:
                records.append({"readable": False, "error_type": type(error).__name__})
            else:
                raise ValueError("forbidden worker isolation canary is readable")
        boundaries[kind] = records
    return {
        "nonce": nonce,
        "hostname": socket.gethostname(),
        "pid": os.getpid(),
        "python_version": sys.version.split()[0],
        "agent_readable": True,
        "agent_sha256": sha256(payload).hexdigest(),
        "boundaries": boundaries,
        "forbidden_reads": [row for rows in boundaries.values() for row in rows],
    }


def validate_worker_binding(
    probe: dict, info: dict, *, nonce: str, agent_sha256: str
) -> None:
    from scripts.dedale_task12_runtime import validate_probe_binding

    validate_probe_binding(probe, info, nonce=nonce, agent_sha256=agent_sha256)
    if (
        probe.get("pid") != 1
        or set(probe.get("boundaries", {})) != {"scoring", "git", "other_case"}
        or any(
            not values or any(row.get("readable") is not False for row in values)
            for values in probe["boundaries"].values()
        )
    ):
        raise ValueError("same worker PID and every read boundary must be verified")


def validate_service_probe_binding(
    evidence: dict, *, probe: dict, spec: dict, source_commit: str, output: Path
) -> None:
    """Bind the independently audited service proof to the inspected worker."""
    from evals.contracts import canonical_hash
    from evals.datasets.dedale.common import read_json, safe_file
    from evals.runners.manifest import file_hash

    if (
        not isinstance(evidence, dict)
        or any(
            not isinstance(evidence.get(key), dict)
            for key in ("provenance", "cleanup", "unchanged", "artifact")
        )
        or any(
            not isinstance(evidence.get(key), list)
            or any(not isinstance(row, dict) for row in evidence[key])
            for key in ("checks", "physical_audit")
        )
    ):
        raise ValueError("service isolation evidence structure is invalid")
    provenance = evidence.get("provenance", {})
    expected = {
        "worker_pid": probe["pid"],
        "worker_nonce": probe["nonce"],
        "container_hostname": probe["hostname"],
        "source_commit": source_commit,
        "input_sha256": probe["agent_sha256"],
        "phase": "development",
        **{key: spec[key] for key in ("run_id", "case_id", "group")},
    }
    names = {
        "positive_alert_context",
        "existing_foreign_alert",
        "forbidden_case_filter",
        "top_level_index",
        "top_level_index_name",
        "window_from_minus_one_second",
        "window_to_plus_one_second",
        "anchor_replacement",
        "dataset_replacement",
    }
    checks = evidence.get("checks", [])
    audit = evidence.get("physical_audit", [])
    before = evidence.get("model_ledger_before_sha256")
    if (
        spec["group"] != "B3"
        or evidence.get("status") != "passed"
        or evidence.get("passed") is not True
        or any(provenance.get(key) != value for key, value in expected.items())
        or provenance.get("database_backend") != "postgresql"
        or provenance.get("actual_database_name") != provenance.get("database_name")
        or not re.fullmatch(r"task13_[0-9a-f]{32}", provenance.get("database_name", ""))
        or not re.fullmatch(
            r"security-events-task13-[0-9a-f]{32}", provenance.get("index_name", "")
        )
        or evidence.get("cleanup", {}).get("verified") is not True
        or evidence.get("unchanged", {}).get("verified") is not True
        or evidence.get("model_calls_made") != 0
        or evidence.get("logical_tool_calls_made") != 0
        or not isinstance(before, str)
        or not re.fullmatch(r"[0-9a-f]{64}", before)
        or before != evidence.get("model_ledger_after_sha256")
        or len(checks) != len(names)
        or {check.get("name") for check in checks} != names
        or any(check.get("passed") is not True for check in checks)
        or len(audit) != 9
        or canonical_hash(audit) != evidence.get("physical_audit_sha256")
        or sum(row.get("success") is True for row in audit) != 1
        or sum(row.get("error_code") == "NOT_FOUND" for row in audit) != 1
        or sum(row.get("error_code") == "POLICY_DENIED" for row in audit) != 7
    ):
        raise ValueError(
            "service isolation evidence is incomplete or belongs to a different worker"
        )
    artifact = evidence.get("artifact", {})
    if artifact.get("path") != "service-isolation-probe.json":
        raise ValueError("service probe artifact path differs")
    path = safe_file(output, "service-isolation-probe.json")
    if not path.is_file() or file_hash(path) != artifact.get("sha256"):
        raise ValueError("service probe artifact hash differs")
    payload = {
        key: value
        for key, value in evidence.items()
        if key
        not in {
            "artifact",
            "model_ledger_before_sha256",
            "model_ledger_after_sha256",
        }
    }
    if canonical_hash(read_json(path)) != canonical_hash(payload):
        raise ValueError(
            "service probe artifact content differs from returned evidence"
        )


def observed_model_invocations(ledger: list[dict]) -> int:
    """Count observed provider replies, preserving failed dispatches separately."""
    count = 0
    for call in ledger:
        raw = call.get("raw_response")
        status = call.get("http_status")
        if (
            type(status) is int
            and 200 <= status < 300
            and isinstance(raw, dict)
            and isinstance(call.get("request_id"), str)
            and bool(call["request_id"])
            and isinstance(call.get("response_model"), str)
            and bool(call["response_model"])
            and raw.get("id") == call["request_id"]
            and raw.get("model") == call["response_model"]
        ):
            count += 1
    return count


def preserve_worker_stdout(output: Path, payload: bytes) -> dict:
    """Seal exact worker bytes in a controller-only sibling before validation."""
    capture = Path(output).parent / (Path(output).name + ".controller")
    capture.mkdir(exist_ok=False)
    path = capture / "worker-stdout.bin"
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    receipt = {
        "schema_version": "task13-worker-stdout-v1",
        "path": str(path.resolve()),
        "sha256": sha256(payload).hexdigest(),
        "bytes": len(payload),
    }
    with (capture / "receipt.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(receipt, stream, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return receipt


def quarantine_isolation_failure(value: dict, raw_stdout: dict, stage: str) -> dict:
    """Exclude unsafe diagnosis while retaining every response and charged ledger."""
    return {
        **value,
        **({"status": "failed"} if "status" in value else {}),
        "execution_status": "failed",
        "diagnosis_status": "failed",
        "diagnostic_snapshot": None,
        "product_status": "isolation_failed",
        "errors": [
            *value.get("errors", []),
            {
                "category": "application",
                "error_type": "WorkerIsolationBindingError",
                "stage": stage,
            },
        ],
        "artifact_hashes": {
            **value.get("artifact_hashes", {}),
            "worker_raw_stdout": raw_stdout["sha256"],
        },
    }


def validate_worker_inspection(
    info: dict,
    expected_mounts: dict[str, str],
    network: str,
    *,
    schema_version: str | None = None,
) -> dict:
    from scripts.dedale_task12_runtime import (
        _host_source,
        validate_container_inspection,
    )

    host = info.get("HostConfig", {})
    _, writable = mount_policy(schema_version)
    if (
        host.get("PidsLimit") != 256
        or host.get("Memory") != 2 * 1024**3
        or host.get("NanoCpus") != 2 * 10**9
    ):
        raise ValueError("worker resource bounds differ from the declared limits")
    actual = info.get("Mounts", [])
    if len(actual) != len(expected_mounts):
        raise ValueError("unexpected worker mount count")
    read_info = {
        **info,
        "Mounts": [row for row in actual if row["Destination"] not in writable],
    }
    accepted = validate_container_inspection(
        read_info,
        {key: value for key, value in expected_mounts.items() if key not in writable},
        network,
    )
    for mount in actual:
        target = mount["Destination"]
        if target in writable and (
            mount.get("RW") is not True
            or mount.get("Type") != "bind"
            or target not in expected_mounts
            or _host_source(mount["Source"]) != _host_source(expected_mounts[target])
        ):
            raise ValueError(
                "writable worker storage is not the exact budget/output boundary"
            )
    accepted["writable_mounts"] = sorted(
        target for target in expected_mounts if target in writable
    )
    return accepted


def export_source(commit: str, destination: Path, *, repository: Path) -> dict:
    from evals.datasets.dedale.common import safe_file
    from evals.runners.manifest import write_immutable_json

    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("source export requires a full immutable commit")
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    archive = subprocess.run(
        ["git", "archive", "--format=zip", commit, *EXPORT_PATHS],
        cwd=repository,
        capture_output=True,
        check=True,
    ).stdout
    files = {}
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        for member in bundle.infolist():
            if member.is_dir():
                continue
            if (member.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("source export cannot contain filesystem links")
            target = safe_file(destination, member.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            payload = bundle.read(member)
            with target.open("xb") as stream:
                stream.write(payload)
            files[member.filename] = sha256(payload).hexdigest()
    if not {
        "evals/contracts.py",
        "evals/adapters/evidencesoc.py",
        "scripts/task13_worker_runtime.py",
    }.issubset(files):
        raise ValueError(
            "committed source does not contain the real Task13 implementation"
        )
    receipt = {
        "source_commit": commit,
        "archive_sha256": sha256(archive).hexdigest(),
        "files": files,
    }
    write_immutable_json(destination / "source_receipt.json", receipt)
    return receipt


def _validate_source(root: Path, commit: str) -> None:
    from evals.datasets.dedale.common import read_json, safe_file
    from evals.runners.manifest import file_hash

    receipt = read_json(root / "source_receipt.json")
    if receipt.get("source_commit") != commit or not receipt.get("files"):
        raise ValueError("worker source commit differs from source export receipt")
    repository = Path(__file__).resolve().parents[1]
    archive = subprocess.run(
        ["git", "archive", "--format=zip", commit, *EXPORT_PATHS],
        cwd=repository,
        capture_output=True,
        check=True,
    ).stdout
    if sha256(archive).hexdigest() != receipt.get("archive_sha256"):
        raise ValueError(
            "worker source archive differs from the actual committed implementation"
        )
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        committed = {
            member.filename: sha256(bundle.read(member)).hexdigest()
            for member in bundle.infolist()
            if not member.is_dir()
        }
    if committed != receipt["files"]:
        raise ValueError(
            "worker source receipt differs from actual committed file hashes"
        )
    expected = set(receipt["files"]) | {"source_receipt.json"}
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink() or path.is_junction():
            raise ValueError("worker source contains a filesystem link")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    if actual != expected:
        raise ValueError("worker source export contains unregistered files")
    for relative, digest in receipt["files"].items():
        if file_hash(safe_file(root, relative)) != digest:
            raise ValueError("worker source export hash differs")


def preflight_runtime(options: dict, controller: dict) -> None:
    from evals.adapters.model_client import BudgetAccount
    from evals.datasets.dedale.common import read_json
    from evals.runners.manifest import ROOT, file_hash

    required = {
        "source_dir",
        "source_commit",
        "image_id",
        "network",
        "dependencies_dir",
        "dependencies_lock_sha256",
        "knowledge_dir",
        "knowledge_sha256",
        "budget_dir",
        "output_dir",
        "phase",
    }
    if not required.issubset(options):
        raise ValueError("real worker runtime configuration is incomplete")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", options["image_id"]) or options[
        "network"
    ] in {"host", "none", ""}:
        raise ValueError("real worker image digest or network is invalid")
    if not os.environ.get("DEEPSEEK_API_KEY"):
        raise ValueError("explicit model credential is unavailable")
    _validate_source(Path(options["source_dir"]), controller["source_commit"])
    dependencies = Path(options["dependencies_dir"])
    receipt = read_json(dependencies / "task13_dependencies.json")
    if (
        receipt.get("lock_sha256") != options["dependencies_lock_sha256"]
        or options["dependencies_lock_sha256"]
        != file_hash(ROOT / "services/backend/uv.lock")
        or dependency_tree_hash(dependencies) != receipt.get("tree_sha256")
    ):
        raise ValueError("real worker dependencies differ from the frozen project lock")
    if (
        dependency_tree_hash(Path(options["knowledge_dir"]))
        != options["knowledge_sha256"]
    ):
        raise ValueError("real worker knowledge snapshot hash differs")
    for arguments in [
        ["image", "inspect", options["image_id"]],
        ["network", "inspect", options["network"]],
    ]:
        checked = subprocess.run(
            ["docker", *arguments], check=False, capture_output=True, timeout=15
        )
        if checked.returncode:
            raise WorkerInfrastructureError(
                "Docker image/network inspection is unavailable"
            )
    budget_path = Path(options["budget_dir"]) / "campaign.sqlite"
    BudgetAccount(
        budget_path,
        total_cny=controller["budget_cny"],
        dev_cny=controller["dev_budget_cny"],
    )


def _worker_request(spec: dict):
    if spec.get("schema_version") == EPOCH_REGRESSION_SCHEMA:
        from evals.adapters.epoch_remediation import EpochRemediationRequest

        return EpochRemediationRequest.model_validate(spec)
    if spec.get("schema_version") == E_PLANNING_REVIEW_SCHEMA:
        from evals.adapters.e_planning_review import EPlanningReviewRequest

        return EPlanningReviewRequest.model_validate(spec)
    if spec.get("schema_version") == E_PLANNING_SCHEMA:
        from evals.adapters.e_planning_contracts import EPlanningRequest

        return EPlanningRequest.model_validate(spec)
    if spec.get("schema_version") == "task13-remediation-review-worker-v2":
        from evals.adapters.remediation_review import RemediationReviewRequest

        return RemediationReviewRequest.model_validate(spec)
    if spec.get("schema_version") == "task13-remediation-worker-v2":
        from evals.adapters.remediation_contracts import RemediationRequest

        return RemediationRequest.model_validate(spec)
    if spec.get("schema_version") == "task13-source-review-worker-v1":
        from evals.adapters.verification_worker import SourceReviewRequest

        return SourceReviewRequest.model_validate(spec)
    if spec.get("schema_version") == "task13-verification-worker-v1":
        from evals.adapters.verification_worker import VerificationWorkerRequest

        return VerificationWorkerRequest.model_validate(spec)
    from evals.contracts import WorkerRunSpec

    return WorkerRunSpec.model_validate(spec)


async def _invoke_adapter(request, agent_dir: Path):
    if getattr(request, "schema_version", None) == EPOCH_REGRESSION_SCHEMA:
        from evals.adapters.epoch_remediation import run_epoch_remediation

        return await run_epoch_remediation(request, agent_dir)
    if getattr(request, "schema_version", None) == E_PLANNING_REVIEW_SCHEMA:
        from evals.adapters.e_planning_review import run_e_planning_review

        return await run_e_planning_review(request, agent_dir)
    if getattr(request, "schema_version", None) == E_PLANNING_SCHEMA:
        from evals.adapters.e_planning_worker import run_e_planning

        return await run_e_planning(request, agent_dir)
    if (
        getattr(request, "schema_version", None)
        == "task13-remediation-review-worker-v2"
    ):
        from evals.adapters.remediation_review import run_remediation_review

        return await run_remediation_review(request, agent_dir)
    if getattr(request, "schema_version", None) == "task13-remediation-worker-v2":
        from evals.adapters.remediation_worker import run_remediation

        return await run_remediation(request, agent_dir)
    if getattr(request, "schema_version", None) == "task13-source-review-worker-v1":
        from evals.adapters.verification_worker import run_source_review

        return await run_source_review(request, agent_dir)
    if getattr(request, "schema_version", None) == "task13-verification-worker-v1":
        from evals.adapters.verification_worker import run_verification

        return await run_verification(request, agent_dir)
    from evals.adapters.evidencesoc import run_case

    return await run_case(request, agent_dir)


async def run_verification_container(request, agent_dir: Path, options: dict) -> dict:
    spec = (
        request.model_dump(mode="json") if hasattr(request, "model_dump") else request
    )
    if spec.get("schema_version") != "task13-verification-worker-v1":
        raise ValueError(
            "verification worker requires its dedicated answer-free schema"
        )
    value = await run_container(spec, agent_dir, options)
    if value.get("model_ledger"):
        raise ValueError("deterministic verification worker cannot make model calls")
    return value


async def run_e_planning_container(request, agent_dir: Path, options: dict) -> dict:
    spec = (
        request.model_dump(mode="json") if hasattr(request, "model_dump") else request
    )
    if spec.get("schema_version") != E_PLANNING_SCHEMA:
        raise ValueError("planning requires its dedicated worker schema")
    return await run_container(spec, agent_dir, options)


async def run_e_planning_review_container(
    request, agent_dir: Path, options: dict
) -> dict:
    spec = (
        request.model_dump(mode="json") if hasattr(request, "model_dump") else request
    )
    if spec.get("schema_version") != E_PLANNING_REVIEW_SCHEMA:
        raise ValueError("planning review requires its dedicated worker schema")
    from evals.adapters.e_planning_review import require_review_window

    require_review_window()
    value = await run_container(spec, agent_dir, options)
    if value.get("model_ledger"):
        raise ValueError("planning reads and decisions cannot make model calls")
    return value


async def run_source_review_container(request, agent_dir: Path, options: dict) -> dict:
    spec = (
        request.model_dump(mode="json") if hasattr(request, "model_dump") else request
    )
    if spec.get("schema_version") != "task13-source-review-worker-v1":
        raise ValueError("source review requires its dedicated worker schema")
    value = await run_container(spec, agent_dir, options)
    if spec["operation"] != "renew_plan" and value.get("model_ledger"):
        raise ValueError(
            "source packet reads and user decisions cannot make model calls"
        )
    return value


async def run_remediation_container(request, agent_dir: Path, options: dict) -> dict:
    spec = (
        request.model_dump(mode="json") if hasattr(request, "model_dump") else request
    )
    if spec.get("schema_version") not in {
        "task13-remediation-worker-v2",
        EPOCH_REGRESSION_SCHEMA,
    }:
        raise ValueError("remediation requires its dedicated versioned worker schema")
    return await run_container(spec, agent_dir, options)


async def run_remediation_review_container(
    request, agent_dir: Path, options: dict
) -> dict:
    spec = (
        request.model_dump(mode="json") if hasattr(request, "model_dump") else request
    )
    if spec.get("schema_version") != "task13-remediation-review-worker-v2":
        raise ValueError("remediation review requires its dedicated v2 worker schema")
    value = await run_container(spec, agent_dir, options)
    if spec["operation"] != "renew_plan" and value.get("model_ledger"):
        raise ValueError("source reads and decisions cannot make model calls")
    return value


async def run_container(spec: dict, agent_dir: Path, options: dict) -> dict:
    from evals.datasets.dedale.common import read_json
    from evals.runners.manifest import file_hash, write_immutable_json

    request = _worker_request(spec)
    epoch_regression = (
        getattr(request, "schema_version", None) == EPOCH_REGRESSION_SCHEMA
    )
    planning_review = (
        getattr(request, "schema_version", None) == E_PLANNING_REVIEW_SCHEMA
    )
    planning = getattr(request, "schema_version", None) in {
        E_PLANNING_SCHEMA,
        E_PLANNING_REVIEW_SCHEMA,
    }
    planning_request = request.planning_request if planning_review else request
    if planning_review:
        from evals.adapters.e_planning_review import require_review_window

        require_review_window()
    verification = (
        getattr(request, "schema_version", None) == "task13-verification-worker-v1"
    )
    termination_dir = options.get("host_termination_dir")
    if termination_dir is not None and not verification:
        raise ValueError(
            "host termination evidence is restricted to verification workers"
        )
    remediation_review = (
        getattr(request, "schema_version", None)
        == "task13-remediation-review-worker-v2"
    )
    source_review = (
        planning_review
        or remediation_review
        or (
            getattr(request, "schema_version", None) == "task13-source-review-worker-v1"
        )
    )
    remediation = epoch_regression or (
        getattr(request, "schema_version", None) == "task13-remediation-worker-v2"
    )
    if (
        verification or source_review or planning
    ) and request.agent_sha256 != file_hash(agent_dir / "events.jsonl"):
        raise ValueError("verification source case input hash differs")
    if source_review and request.source_commit != options["source_commit"]:
        raise ValueError("source review implementation commit differs from runtime")
    model_allowed = not verification and (
        not source_review or request.operation == "renew_plan"
    )
    source = Path(options["source_dir"]).resolve()
    _validate_source(source, options["source_commit"])
    if remediation or remediation_review:
        from evals.adapters.remediation_worker import (
            require_existing_budget,
            validate_binding,
            validate_exported_source,
        )

        validator = validate_exported_source if remediation_review else validate_binding
        validator(request, agent_dir, source, source_commit=options["source_commit"])
        expected_phase = (
            "verification"
            if remediation_review
            else "development"
            if request.purpose == "development"
            else "formal"
        )
        if options["phase"] != expected_phase:
            raise ValueError(
                "remediation runtime phase differs from registered purpose"
            )
        if options.get("budget_identity") != request.budget_identity:
            raise ValueError(
                "remediation runtime budget identity differs from registered request"
            )
        require_existing_budget(
            Path(options["budget_dir"]) / "campaign.sqlite", request.budget_identity
        )
    dependencies = Path(options["dependencies_dir"]).resolve()
    required = [
        "mcp",
        "langgraph",
        "langchain_openai",
        "fastembed",
        "pydantic",
        "sqlalchemy",
        "httpx",
    ]
    if any(not (dependencies / module).is_dir() for module in required):
        raise ValueError("full locked Linux workflow dependencies are unavailable")
    dependency_receipt = read_json(dependencies / "task13_dependencies.json")
    if (
        dependency_receipt.get("lock_sha256") != options["dependencies_lock_sha256"]
        or dependency_receipt.get("platform") != "linux-amd64"
    ):
        raise ValueError("Linux dependency lock receipt differs")
    if dependency_tree_hash(dependencies) != dependency_receipt.get("tree_sha256"):
        raise ValueError("Linux dependency contents differ from frozen receipt")
    knowledge = Path(options["knowledge_dir"]).resolve()
    if dependency_tree_hash(knowledge) != options.get("knowledge_sha256"):
        raise ValueError("frozen knowledge snapshot hash differs")
    planning_runtime = (
        validate_e_planning_host(
            planning_request,
            agent_dir,
            options,
            dependency_receipt,
            review=planning_review,
        )
        if planning
        else None
    )
    epoch_manifest = None
    epoch_runtime = None
    if epoch_regression:
        from evals.adapters.epoch_remediation import validate_epoch_runtime

        epoch_runtime = e_planning_runtime_binding(options, dependency_receipt)
        epoch_manifest = validate_epoch_runtime(
            request,
            agent_dir,
            source,
            Path(options["budget_dir"]) / "campaign.sqlite",
            epoch_runtime,
            options["source_commit"],
            worker=False,
        )
    nonce = uuid.uuid4().hex
    name = "task13-worker-" + nonce
    budget = Path(options["budget_dir"]).resolve()
    budget.mkdir(parents=True, exist_ok=True)
    output = (
        Path(options["output_dir"]).resolve()
        / (
            "source_review"
            if source_review
            else "verification"
            if verification
            else spec["run_id"]
        )
        / spec["case_id"]
        / (spec["request_id"] if verification or source_review else spec["group"])
        / nonce
    )
    output.mkdir(parents=True, exist_ok=False)
    staging = Path(
        options.get(
            "temporary_root", str(Path(options["output_dir"]) / ".controller-staging")
        )
    )
    staging.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="task13-runtime-", dir=staging
    ) as temporary:
        spec_path = Path(temporary) / "spec.json"
        write_immutable_json(spec_path, spec)
        canaries = {}
        for kind in ["scoring", "git", "other_case"]:
            canary = Path(temporary) / kind / "canary.txt"
            canary.parent.mkdir()
            canary.write_text(uuid.uuid4().hex, encoding="utf-8")
            canaries[kind] = [
                str(canary.resolve()),
                f"/app/{kind}/canary.txt",
                f"/workspace/{kind}/canary.txt",
            ]
        canaries["git"] += [
            "/app/source/.git/config",
            "/app/.git/config",
            "/.git/config",
        ]
        mounts = {
            "/app/agent": str(agent_dir.resolve()),
            "/app/source": str(source),
            "/app/spec.json": str(spec_path.resolve()),
            "/app/runtime.py": str(source / "scripts/task13_worker_runtime.py"),
            "/opt/task13-deps": str(dependencies),
            "/app/knowledge": str(Path(options["knowledge_dir"]).resolve()),
            "/app/budget": str(budget),
            "/app/output": str(output),
        }
        if planning:
            mounts.update(
                {
                    "/app/import-source": str(
                        Path(options["import_source_dir"]).resolve()
                    ),
                    "/app/import-dispatch": str(
                        Path(options["import_dispatch_path"]).resolve().parent
                    ),
                }
            )
        environment = {
            key: os.environ[key]
            for key in ["PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"]
            if key in os.environ
        }
        passed = {
            key: os.environ[key]
            for key in [
                *(["DEEPSEEK_API_KEY"] if model_allowed else []),
                "DATABASE_URL",
                "OPENSEARCH_URL",
                "OPENSEARCH_INDEX",
            ]
            if key in os.environ
        }
        passed.update(
            {
                "PYTHONPATH": "/app/source:/app/source/services/backend/src:/opt/task13-deps",
                "PYTHONDONTWRITEBYTECODE": "1",
                "TASK13_WORKER_NONCE": nonce,
                "TASK13_SOURCE_COMMIT": options["source_commit"],
                "TASK13_FORBIDDEN_PATHS": json.dumps(canaries),
                "TASK13_BUDGET_DB": "/app/budget/campaign.sqlite",
                "TASK13_OUTPUT_DIR": "/app/output",
                "TASK13_PHASE": "verification"
                if source_review or verification
                else options["phase"],
                "RAG_DATA_DIRECTORY": "/app/knowledge",
                "OPENBLAS_NUM_THREADS": "1",
            }
        )
        if remediation or remediation_review or planning:
            passed["TASK13_SOURCE_DIR"] = "/app/source"
        if epoch_regression:
            passed["TASK13_RUNTIME_BINDING"] = json.dumps(epoch_runtime, sort_keys=True)
            passed["TASK13_EPOCH_HOST_BUDGET_PATH"] = epoch_manifest["budget_path"]
        if planning:
            passed.update(
                {
                    "TASK13_IMPORT_SOURCE_DIR": "/app/import-source",
                    "TASK13_IMPORT_DISPATCH_DB": "/app/import-dispatch/e-planning.sqlite",
                    "TASK13_IMPORT_HOST_JOURNAL_PATH": str(
                        Path(options["import_dispatch_path"]).resolve()
                    ),
                    "TASK13_IMPORT_AUTHORITY_SHA256": options[
                        "planning_authority_sha256"
                    ],
                    "TASK13_RUNTIME_BINDING": json.dumps(
                        planning_runtime, sort_keys=True
                    ),
                }
            )
        environment.update(passed)
        arguments = docker_run_arguments(
            name=name,
            image_id=options["image_id"],
            network=options["network"],
            mounts=mounts,
            environment=passed,
            **({"schema_version": request.schema_version} if planning else {}),
        )
        try:
            process = await asyncio.create_subprocess_exec(
                "docker",
                *arguments,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=environment,
            )
        except OSError as error:
            raise WorkerInfrastructureError(
                "Docker worker startup is unavailable"
            ) from error
        accepted = None
        try:
            line = await asyncio.wait_for(process.stderr.readline(), timeout=30)
            if not line.startswith(PROBE_PREFIX.encode()):
                raise WorkerInfrastructureError(
                    "real worker filesystem probe missing before execution"
                )
            probe = json.loads(line.decode("utf-8").removeprefix(PROBE_PREFIX))
            inspection = await asyncio.create_subprocess_exec(
                "docker",
                "inspect",
                name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=environment,
            )
            raw, _ = await inspection.communicate()
            if inspection.returncode:
                raise WorkerInfrastructureError("real worker Docker inspection failed")
            info = json.loads(raw)[0]
            accepted = validate_worker_inspection(
                info,
                mounts,
                options["network"],
                **({"schema_version": request.schema_version} if planning else {}),
            )
            if accepted["image_id"] != options["image_id"]:
                raise ValueError("worker image digest differs from frozen runtime")
            if probe.get("python_version") != dependency_receipt["python_version"]:
                raise ValueError(
                    "worker Python ABI differs from locked Linux dependencies"
                )
            validate_worker_binding(
                probe,
                info,
                nonce=nonce,
                agent_sha256=file_hash(agent_dir / "events.jsonl"),
            )
            if planning:
                validate_e_planning_probe(
                    probe.get("planning", {}),
                    planning_request,
                    authority_sha256=options["planning_authority_sha256"],
                )
            process.stdin.write(("GO:" + nonce + "\n").encode())
            await process.stdin.drain()
            process.stdin.close()
            stdout, _ = await asyncio.wait_for(
                process.communicate(), timeout=options.get("case_timeout_seconds", 1800)
            )
            raw_stdout = preserve_worker_stdout(output, stdout)
            if process.returncode:
                raise WorkerInfrastructureError(
                    "real worker failed; sanitized result was not completed"
                )
            value = json.loads(stdout)
            model_binding_failed = bool(not model_allowed and value.get("model_ledger"))
            for call in value.get("model_ledger", []):
                if (
                    call.get("worker_pid") != probe["pid"]
                    or call.get("worker_nonce") != nonce
                    or call.get("container_hostname") != probe["hostname"]
                ):
                    model_binding_failed = True
            worker_evidence = value.get("isolation_evidence") or {}
            service_probe = (
                worker_evidence.get("service_probe")
                if isinstance(worker_evidence, dict)
                else worker_evidence
            )
            service_accepted = False
            service_binding = None
            if service_probe is not None:
                try:
                    validate_service_probe_binding(
                        service_probe,
                        probe=probe,
                        spec=spec,
                        source_commit=options["source_commit"],
                        output=output,
                    )
                    service_accepted = True
                    service_binding = {"status": "passed"}
                except (ValueError, OSError, KeyError, TypeError) as error:
                    # Preserve every paid result and failure artifact; reject G4.
                    service_binding = {
                        "status": "failed",
                        "error_type": type(error).__name__,
                    }
            service_probe_required = (
                not verification
                and not source_review
                and options["phase"] == "development"
                and spec.get("group") == "B3"
            )
            isolation_failed = (
                model_binding_failed
                or (service_probe is not None and not service_accepted)
                or (service_probe_required and service_probe is None)
            )
            if isolation_failed:
                value = quarantine_isolation_failure(
                    value,
                    raw_stdout,
                    "model_binding"
                    if model_binding_failed
                    else "service_probe_binding",
                )
            value["isolation_evidence"] = {
                "status": "failed" if isolation_failed else "passed",
                "probe": probe,
                "container": accepted,
                "source_commit": options["source_commit"],
                "real_model_invocations": observed_model_invocations(
                    value.get("model_ledger", [])
                ),
                "model_physical_attempts": len(value.get("model_ledger", [])),
                "raw_stdout": raw_stdout,
                "canary_hashes": {
                    key: file_hash(Path(paths[0])) for key, paths in canaries.items()
                },
                **(
                    {
                        "service_probe": service_probe,
                        "service_probe_binding": service_binding,
                    }
                    if service_probe is not None
                    else {}
                ),
                **(
                    {
                        "cross_case_denied": service_accepted,
                        "critical_skips": 0 if service_accepted else 1,
                    }
                    if service_probe is not None or service_probe_required
                    else {}
                ),
            }
            return value
        except (ConnectionError, TimeoutError) as error:
            raise WorkerTransportError(
                "worker communication was interrupted"
            ) from error
        except OSError as error:
            raise WorkerInfrastructureError(
                "Docker worker process is unavailable"
            ) from error
        finally:
            if termination_dir is not None:
                from evals.contracts import canonical_hash
                from evals.worker_lifecycle import capture_worker_termination

                termination = asyncio.create_task(
                    capture_worker_termination(
                        process=process,
                        name=name,
                        nonce=nonce,
                        container_id=accepted.get("container_id") if accepted else None,
                        request_sha256=canonical_hash(spec),
                        source_commit=options["source_commit"],
                        environment=environment,
                        receipt_dir=termination_dir,
                    )
                )
                try:
                    await asyncio.shield(termination)
                except asyncio.CancelledError:
                    # Keep the cleanup proof running even if an outer deadline
                    # cancels this coroutine a second time. Missing proof stays
                    # unknown at the controller; it never authorizes replay.
                    await termination
                    raise
            elif process.returncode is None:
                stop = await asyncio.create_subprocess_exec(
                    "docker",
                    "rm",
                    "-f",
                    name,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    env=environment,
                )
                await stop.wait()
                await process.wait()


def main() -> None:
    forbidden = {
        kind: [Path(value) for value in values]
        for kind, values in json.loads(os.environ["TASK13_FORBIDDEN_PATHS"]).items()
    }
    nonce = os.environ["TASK13_WORKER_NONCE"]
    probe = worker_probe(Path("/app/agent/events.jsonl"), forbidden, nonce)
    if os.environ.get("TASK13_IMPORT_SOURCE_DIR"):
        request = _worker_request(json.loads(Path("/app/spec.json").read_bytes()))
        if request.schema_version not in {E_PLANNING_SCHEMA, E_PLANNING_REVIEW_SCHEMA}:
            raise ValueError("only planning workers may mount import resources")
        probe["planning"] = e_planning_worker_probe(
            request.planning_request
            if request.schema_version == E_PLANNING_REVIEW_SCHEMA
            else request
        )
    sys.stderr.write(PROBE_PREFIX + json.dumps(probe, sort_keys=True) + "\n")
    sys.stderr.flush()
    if sys.stdin.readline().strip() != "GO:" + nonce:
        raise RuntimeError("controller did not authorize the inspected worker")
    try:
        spec = _worker_request(
            json.loads(Path("/app/spec.json").read_text(encoding="utf-8"))
        )
        result = asyncio.run(_invoke_adapter(spec, Path("/app/agent")))
    except Exception as error:  # noqa: BLE001 - preserve typed failures without secrets/tracebacks.
        from evals.adapters.worker_errors import exception_category

        result = {
            "execution_status": "failed",
            "diagnosis_status": "failed",
            "errors": [
                {
                    "category": exception_category(error),
                    "error_type": type(error).__name__,
                }
            ],
        }
    payload = (
        result.model_dump(mode="json") if hasattr(result, "model_dump") else result
    )
    sys.stdout.write(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
    )
    sys.stdout.flush()


def cli() -> None:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser(
        "export-source",
        help="Export only required implementation from a full Git commit",
    )
    export.add_argument("--commit", required=True)
    export.add_argument("--destination", type=Path, required=True)
    export.add_argument("--repository", type=Path, default=Path.cwd())
    dependencies = commands.add_parser(
        "prepare-dependencies",
        help="Install hashed locked wheels for the explicit Linux Python ABI",
    )
    dependencies.add_argument("--destination", type=Path, required=True)
    dependencies.add_argument("--python-version", required=True)
    dependencies.add_argument("--repository", type=Path, default=Path.cwd())
    args = parser.parse_args()
    if args.command == "export-source":
        receipt = export_source(
            args.commit, args.destination, repository=args.repository
        )
        print(
            json.dumps(
                {
                    "source_commit": receipt["source_commit"],
                    "file_count": len(receipt["files"]),
                }
            )
        )
    else:
        receipt = prepare_dependencies(
            repository=args.repository,
            destination=args.destination,
            python_version=args.python_version,
        )
        print(
            json.dumps(
                {
                    key: receipt[key]
                    for key in ["platform", "python_version", "lock_sha256"]
                }
            )
        )


if __name__ == "__main__":
    if "TASK13_WORKER_NONCE" in os.environ:
        main()
    else:
        cli()
