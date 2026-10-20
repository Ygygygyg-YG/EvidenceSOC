"""Task13 probes belong to the real model worker and fail closed."""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import io
import json
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest


def runtime():
    assert importlib.util.find_spec("scripts.task13_worker_runtime") is not None
    return importlib.import_module("scripts.task13_worker_runtime")


@pytest.mark.parametrize(
    "failure,review_operation",
    [
        ("startup", None),
        ("probe", None),
        ("process", None),
        ("process", "read_packet"),
        ("process", "decision"),
        ("process", "renew_plan"),
        ("binding", None),
    ],
)
def test_docker_failures_keep_typed_errors_and_quarantine_paid_binding_failure(
    tmp_path, monkeypatch, failure, review_operation
):
    module = runtime()
    errors = importlib.import_module("evals.adapters.worker_errors")
    dependencies = tmp_path / "deps"
    for name in [
        "mcp",
        "langgraph",
        "langchain_openai",
        "fastembed",
        "pydantic",
        "sqlalchemy",
        "httpx",
    ]:
        (dependencies / name).mkdir(parents=True)
    (dependencies / "task13_dependencies.json").write_text(
        json.dumps(
            {
                "lock_sha256": "a" * 64,
                "platform": "linux-amd64",
                "tree_sha256": "b" * 64,
                "python_version": "3.12.14",
            }
        ),
        encoding="utf-8",
    )
    agent = tmp_path / "agent"
    agent.mkdir()
    (agent / "events.jsonl").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(module, "_validate_source", lambda *args: None)
    monkeypatch.setattr(
        module,
        "_worker_request",
        lambda spec: SimpleNamespace(
            schema_version="task13-source-review-worker-v1"
            if review_operation
            else None,
            operation=review_operation,
            source_commit="a" * 40,
            agent_sha256=sha256((agent / "events.jsonl").read_bytes()).hexdigest(),
        ),
    )
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic-no-call-key")
    child_environments = []
    monkeypatch.setattr(module, "dependency_tree_hash", lambda root: "b" * 64)
    monkeypatch.setattr(
        module,
        "validate_worker_inspection",
        lambda *args: {"image_id": "sha256:" + "c" * 64},
    )
    monkeypatch.setattr(module, "validate_worker_binding", lambda *args, **kwargs: None)

    class Process:
        returncode = 1

        def __init__(self, inspect=False):
            self.inspect = inspect
            self.stderr = self
            self.stdin = self

        async def readline(self):
            if failure == "probe":
                return b"Docker startup failed"
            return (
                module.PROBE_PREFIX
                + json.dumps(
                    {
                        "python_version": "3.12.14",
                        "pid": 1,
                        "nonce": "inspected",
                        "hostname": "inspected",
                        "agent_sha256": "a" * 64,
                    }
                )
            ).encode()

        async def communicate(self):
            if self.inspect:
                self.returncode = 0
                return b"[{}]", b""
            if failure == "binding":
                self.returncode = 0
                return json.dumps(
                    {
                        "execution_status": "completed",
                        "diagnosis_status": "succeeded",
                        "diagnostic_snapshot": {"diagnosis": {"verdict": "attack"}},
                        "model_ledger": [
                            {
                                "worker_pid": 999,
                                "worker_nonce": "foreign",
                                "container_hostname": "foreign",
                                "cost_cny": 0.05,
                                "raw_response": {"id": "paid"},
                            }
                        ],
                        "resources": {"cost": 0.05},
                    }
                ).encode(), b""
            return b"", b"private error with secret credential"

        def write(self, data):
            pass

        async def drain(self):
            pass

        def close(self):
            pass

    async def spawn(*arguments, **kwargs):
        child_environments.append(kwargs["env"])
        if failure == "startup":
            raise OSError("private Docker endpoint")
        return Process(inspect=arguments[1] == "inspect")

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", spawn)
    options = {
        "source_dir": str(tmp_path / "source"),
        "source_commit": "a" * 40,
        "dependencies_dir": str(dependencies),
        "dependencies_lock_sha256": "a" * 64,
        "knowledge_dir": str(tmp_path / "knowledge"),
        "knowledge_sha256": "b" * 64,
        "budget_dir": str(tmp_path / "budget"),
        "output_dir": str(tmp_path / "output"),
        "image_id": "sha256:" + "c" * 64,
        "network": "task13",
        "phase": "development",
    }
    spec = {"run_id": "run", "case_id": "ait-" + "0" * 24, "group": "B0"}
    if review_operation:
        spec.update(
            schema_version="task13-source-review-worker-v1", request_id="f" * 32
        )
    if failure == "binding":
        from evals.contracts import AdapterResult

        result = AdapterResult.model_validate(
            asyncio.run(module.run_container(spec, agent, options))
        )
        assert result.execution_status == result.diagnosis_status == "failed"
        assert result.diagnostic_snapshot is None
        assert result.model_ledger[0]["cost_cny"] == 0.05
        assert result.resources["cost"] == 0.05
        assert result.isolation_evidence["status"] == "failed"
        raw = Path(result.isolation_evidence["raw_stdout"]["path"])
        assert (
            json.loads(raw.read_bytes())["diagnostic_snapshot"]["diagnosis"]["verdict"]
            == "attack"
        )
        assert (
            result.artifact_hashes["worker_raw_stdout"]
            == sha256(raw.read_bytes()).hexdigest()
        )
    else:
        with pytest.raises(errors.WorkerInfrastructureError):
            asyncio.run(module.run_container(spec, agent, options))
    if review_operation:
        assert child_environments
        assert ("DEEPSEEK_API_KEY" in child_environments[0]) == (
            review_operation == "renew_plan"
        )
        assert child_environments[0]["TASK13_PHASE"] == "verification"
        assert (
            tmp_path / "output/source_review" / spec["case_id"] / spec["request_id"]
        ).is_dir()


@pytest.mark.parametrize(
    "category", ["infrastructure", "transport", "application", "schema"]
)
def test_bootstrap_serializes_typed_failure_without_secret_or_traceback(
    monkeypatch, capsys, category
):
    module = runtime()
    errors = importlib.import_module("evals.adapters.worker_errors")
    monkeypatch.setenv("TASK13_FORBIDDEN_PATHS", "{}")
    monkeypatch.setenv("TASK13_WORKER_NONCE", "nonce")
    monkeypatch.setattr(
        module, "worker_probe", lambda *args: {"pid": 1, "nonce": "nonce"}
    )
    monkeypatch.setattr(module.sys, "stdin", io.StringIO("GO:nonce\n"))
    monkeypatch.setattr(module.Path, "read_text", lambda *args, **kwargs: "{}")
    monkeypatch.setattr(module, "_worker_request", lambda spec: spec)

    async def adapter(*args):
        if category == "schema":
            from evals.contracts import WorkerRunSpec

            WorkerRunSpec.model_validate({})
        kind = {
            "infrastructure": errors.WorkerInfrastructureError,
            "transport": errors.WorkerTransportError,
            "application": RuntimeError,
        }[category]
        raise kind("secret-credential-that-must-never-appear")

    monkeypatch.setattr(module, "_invoke_adapter", adapter)
    module.main()
    output = capsys.readouterr()
    value = json.loads(output.out)
    assert value["execution_status"] == "failed"
    assert value["errors"][0]["category"] == category
    assert "secret-credential" not in output.out + output.err
    assert "Traceback" not in output.out + output.err


def test_runtime_requires_immutable_source_digest_and_exact_mounts():
    module = runtime()
    mounts = {
        "/app/agent": "D:/case/agent",
        "/app/source": "D:/export/source",
        "/app/spec.json": "D:/run/spec.json",
        "/app/runtime.py": "D:/export/runtime.py",
        "/opt/task13-deps": "D:/deps",
        "/app/knowledge": "D:/knowledge",
    }
    args = module.docker_run_arguments(
        name="task13-worker-0123",
        image_id="sha256:" + "a" * 64,
        network="task13",
        mounts=mounts,
        environment={"DEEPSEEK_API_KEY": "secret"},
    )
    assert "secret" not in " ".join(args)
    assert args.count("--mount") == 6 and "--read-only" in args
    assert "--pull=never" in args and "host" not in args
    with pytest.raises(ValueError):
        module.docker_run_arguments(
            name="task13-worker-0123",
            image_id="latest",
            network="host",
            mounts=mounts,
            environment={},
        )
    with pytest.raises(ValueError):
        module.docker_run_arguments(
            name="task13-worker-0123",
            image_id="sha256:" + "a" * 64,
            network="task13",
            mounts={**mounts, "/repo": "D:/repo"},
            environment={},
        )


def test_probe_checks_git_other_case_and_score_canaries(tmp_path):
    module = runtime()
    agent = tmp_path / "events.jsonl"
    agent.write_bytes(b"{}\n")
    forbidden = {
        "scoring": [tmp_path / "scoring/canary"],
        "git": [tmp_path / ".git/config"],
        "other_case": [tmp_path / "other/events.jsonl"],
    }
    probe = module.worker_probe(agent, forbidden, "nonce")
    assert probe["pid"] > 0 and set(probe["boundaries"]) == set(forbidden)
    assert all(
        row["readable"] is False
        for rows in probe["boundaries"].values()
        for row in rows
    )
    forbidden["other_case"] = [agent]
    with pytest.raises(ValueError, match="readable|isolation"):
        module.worker_probe(agent, forbidden, "nonce")


def test_binding_requires_same_worker_pid():
    module = runtime()
    probe = {
        "nonce": "nonce",
        "hostname": "a" * 12,
        "pid": 77,
        "agent_sha256": "b" * 64,
        "agent_readable": True,
        "forbidden_reads": [{"readable": False}],
        "boundaries": {
            key: [{"readable": False}] for key in ["scoring", "git", "other_case"]
        },
    }
    info = {
        "Id": "a" * 64,
        "Config": {"Hostname": "a" * 12},
        "State": {"Running": True},
    }
    with pytest.raises(ValueError, match="pid|PID|worker"):
        module.validate_worker_binding(
            probe, info, nonce="nonce", agent_sha256="b" * 64
        )
    probe["pid"] = 1
    module.validate_worker_binding(probe, info, nonce="nonce", agent_sha256="b" * 64)


@pytest.mark.parametrize(
    "tamper",
    [
        None,
        "nonce",
        "source",
        "input",
        "audit",
        "cleanup",
        "changed_model",
        "fixture_backend",
        "artifact",
        "malformed_provenance",
        "malformed_checks",
        "malformed_audit",
    ],
)
def test_service_probe_requires_real_worker_binding_and_intact_artifact(
    tmp_path, tamper
):
    from evals.contracts import canonical_hash

    module = runtime()
    assert hasattr(module, "validate_service_probe_binding"), (
        "controller must validate service proof rather than overwrite or trust a boolean"
    )
    filesystem = {
        "pid": 1,
        "nonce": "real-nonce",
        "hostname": "container-host",
        "agent_sha256": "b" * 64,
    }
    spec = {"run_id": "run", "case_id": "ait-" + "0" * 24, "group": "B3"}
    evidence = {
        "status": "passed",
        "passed": True,
        "cleanup": {"verified": True},
        "unchanged": {"verified": True},
        "model_calls_made": 0,
        "logical_tool_calls_made": 0,
        "provenance": {
            "worker_pid": 1,
            "worker_nonce": "real-nonce",
            "container_hostname": "container-host",
            "source_commit": "a" * 40,
            "input_sha256": "b" * 64,
            "phase": "development",
            **spec,
            "database_backend": "postgresql",
            "database_name": "task13_" + "c" * 32,
            "actual_database_name": "task13_" + "c" * 32,
            "index_name": "security-events-task13-" + "c" * 32,
        },
        "physical_audit": [
            {
                "success": number == 0,
                "error_code": None
                if number == 0
                else "NOT_FOUND"
                if number == 1
                else "POLICY_DENIED",
            }
            for number in range(9)
        ],
        "checks": [
            {"name": name, "passed": True}
            for name in (
                "positive_alert_context",
                "existing_foreign_alert",
                "forbidden_case_filter",
                "top_level_index",
                "top_level_index_name",
                "window_from_minus_one_second",
                "window_to_plus_one_second",
                "anchor_replacement",
                "dataset_replacement",
            )
        ],
    }
    evidence["physical_audit_sha256"] = canonical_hash(evidence["physical_audit"])
    path = tmp_path / "service-isolation-probe.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    evidence["artifact"] = {
        "path": path.name,
        "sha256": sha256(path.read_bytes()).hexdigest(),
    }
    evidence["model_ledger_before_sha256"] = canonical_hash([])
    evidence["model_ledger_after_sha256"] = canonical_hash([])
    if tamper == "nonce":
        evidence["provenance"]["worker_nonce"] = "foreign"
    elif tamper == "source":
        evidence["provenance"]["source_commit"] = "d" * 40
    elif tamper == "input":
        evidence["provenance"]["input_sha256"] = "d" * 64
    elif tamper == "audit":
        evidence["physical_audit"] = []
    elif tamper == "cleanup":
        evidence["cleanup"]["verified"] = False
    elif tamper == "changed_model":
        evidence["model_ledger_after_sha256"] = "d" * 64
    elif tamper == "fixture_backend":
        evidence["provenance"]["database_backend"] = "sqlite"
    elif tamper == "artifact":
        path.write_text("{}", encoding="utf-8")
    elif tamper == "malformed_provenance":
        evidence["provenance"] = []
    elif tamper == "malformed_checks":
        evidence["checks"] = [None] * 9
    elif tamper == "malformed_audit":
        evidence["physical_audit"] = [None] * 9
    arguments = {
        "probe": filesystem,
        "spec": spec,
        "source_commit": "a" * 40,
        "output": tmp_path,
    }
    if tamper is None:
        module.validate_service_probe_binding(evidence, **arguments)
    else:
        with pytest.raises(ValueError):
            module.validate_service_probe_binding(evidence, **arguments)


def test_real_model_invocations_require_observed_provider_response():
    module = runtime()
    assert hasattr(module, "observed_model_invocations"), (
        "pre-HTTP reservations cannot establish model-worker acceptance"
    )
    real = {
        "http_status": 200,
        "raw_response": {"id": "actual-request", "model": "actual-model"},
        "request_id": "actual-request",
        "response_model": "actual-model",
        "parse_status": "schema_error",
    }
    assert (
        module.observed_model_invocations(
            [{"parse_status": "not_received"}, {"http_status": 401}, real]
        )
        == 1
    )
    for mutation in (
        {"http_status": 503},
        {"request_id": "different"},
        {"response_model": None},
        {"raw_response": {}},
        {"raw_response": []},
    ):
        assert module.observed_model_invocations([{**real, **mutation}]) == 0


def test_binding_failure_keeps_immutable_raw_stdout_and_all_charged_ledgers(tmp_path):
    module = runtime()
    assert hasattr(module, "preserve_worker_stdout"), (
        "worker output must be sealed before boundary checks"
    )
    assert hasattr(module, "quarantine_isolation_failure")
    output = tmp_path / "worker-mounted"
    output.mkdir()
    value = {
        "execution_status": "completed",
        "diagnosis_status": "succeeded",
        "diagnostic_snapshot": {"diagnosis": {"verdict": "attack"}},
        "model_ledger": [
            {
                "worker_pid": 999,
                "raw_response": {"id": "paid-response"},
                "cost_cny": 0.01,
            }
        ],
        "tool_ledger": [{"charged": True, "attempts": 1}],
        "resources": {"cost": 0.01},
        "errors": [],
    }
    raw = json.dumps(value).encode()
    receipt = module.preserve_worker_stdout(output, raw)
    capture = Path(receipt["path"])
    assert not capture.is_relative_to(output)
    assert capture.read_bytes() == raw and receipt["sha256"] == sha256(raw).hexdigest()
    with pytest.raises(FileExistsError):
        module.preserve_worker_stdout(output, b"must not replace the paid response")
    quarantined = module.quarantine_isolation_failure(value, receipt, "model_binding")
    assert (
        quarantined["execution_status"] == quarantined["diagnosis_status"] == "failed"
    )
    assert quarantined["diagnostic_snapshot"] is None
    assert quarantined["model_ledger"] == value["model_ledger"]
    assert quarantined["tool_ledger"] == value["tool_ledger"]
    assert quarantined["resources"] == value["resources"]
    assert quarantined["errors"][-1]["category"] == "application"
    assert quarantined["artifact_hashes"]["worker_raw_stdout"] == receipt["sha256"]
    assert capture.read_bytes() == raw
    assert (
        module.quarantine_isolation_failure(
            {**value, "status": "completed"}, receipt, "model_binding"
        )["status"]
        == "failed"
    )


def test_dependency_install_commands_use_frozen_lock_and_explicit_linux_abi(tmp_path):
    module = runtime()
    commands = module.dependency_commands(
        repository=tmp_path, destination=tmp_path / "packages", python_version="3.12.14"
    )
    assert (
        commands[0][:2] == ["uv", "export"]
        and "--locked" in commands[0]
        and "--no-emit-project" in commands[0]
    )
    assert commands[1][:3] == ["uv", "pip", "install"]
    assert (
        commands[1][commands[1].index("--python-platform") + 1]
        == "x86_64-manylinux_2_28"
    )
    assert commands[1][commands[1].index("--python-version") + 1] == "3.12.14"
    assert "--require-hashes" in commands[1] and "--no-deps" in commands[1]


def test_dependency_tree_digest_detects_modified_binary_and_ignores_receipt(tmp_path):
    module = runtime()
    (tmp_path / "package").mkdir()
    binary = tmp_path / "package/native.so"
    binary.write_bytes(b"linux-wheel")
    first = module.dependency_tree_hash(tmp_path)
    (tmp_path / "task13_dependencies.json").write_text("{}")
    assert module.dependency_tree_hash(tmp_path) == first
    binary.write_bytes(b"changed-wheel")
    assert module.dependency_tree_hash(tmp_path) != first


def test_nested_receipt_named_files_remain_bound_by_dependency_digest(tmp_path):
    module = runtime()
    package = tmp_path / "package"
    package.mkdir()
    nested = package / "task13_dependencies.json"
    nested.write_text("first payload")
    first = module.dependency_tree_hash(tmp_path)
    nested.write_text("changed payload")
    assert module.dependency_tree_hash(tmp_path) != first


def test_source_receipt_cannot_claim_a_different_git_archive(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace

    module = runtime()
    (tmp_path / "source_receipt.json").write_text(
        json.dumps(
            {
                "source_commit": "a" * 40,
                "archive_sha256": "b" * 64,
                "files": {"evals/contracts.py": "c" * 64},
            }
        )
    )
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=b"different archive"),
    )
    with pytest.raises(ValueError, match="archive"):
        module._validate_source(tmp_path, "a" * 40)


def test_source_export_and_preflight_reject_modified_or_extra_files(
    tmp_path, monkeypatch
):
    import io
    import zipfile
    from types import SimpleNamespace

    module = runtime()
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as bundle:
        for name in [
            "evals/contracts.py",
            "evals/adapters/evidencesoc.py",
            "scripts/task13_worker_runtime.py",
        ]:
            bundle.writestr(name, "# committed source\n")
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(stdout=archive.getvalue()),
    )
    destination = tmp_path / "source"
    receipt = module.export_source("a" * 40, destination, repository=tmp_path)
    assert set(receipt["files"]) == {
        "evals/contracts.py",
        "evals/adapters/evidencesoc.py",
        "scripts/task13_worker_runtime.py",
    }
    module._validate_source(destination, "a" * 40)
    extra = destination / "gold.json"
    extra.write_text("must not enter the worker")
    with pytest.raises(ValueError, match="unregistered"):
        module._validate_source(destination, "a" * 40)
    extra.unlink()
    (destination / "evals/contracts.py").write_text("changed source")
    with pytest.raises(ValueError, match="hash"):
        module._validate_source(destination, "a" * 40)


@pytest.mark.parametrize(
    "key,value", [("PidsLimit", 0), ("Memory", 0), ("NanoCpus", 0)]
)
def test_worker_inspection_rejects_missing_resource_bounds(key, value):
    module = runtime()
    mounts = {
        target: "D:/allowed/" + target.rsplit("/", 1)[-1]
        for target in module.READ_ONLY_MOUNTS | module.WRITABLE_MOUNTS
    }
    info = {
        "Id": "a" * 64,
        "Image": "sha256:" + "b" * 64,
        "State": {"Running": True},
        "Config": {"User": "65532:65532", "Hostname": "a" * 12},
        "HostConfig": {
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges"],
            "PidMode": "",
            "NetworkMode": "task13",
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=256m"},
            "PidsLimit": 256,
            "Memory": 2 * 1024**3,
            "NanoCpus": 2 * 10**9,
        },
        "Mounts": [
            {
                "Destination": target,
                "Source": source,
                "Type": "bind",
                "RW": target in module.WRITABLE_MOUNTS,
            }
            for target, source in mounts.items()
        ],
    }
    module.validate_worker_inspection(info, mounts, "task13")
    info["HostConfig"][key] = value
    with pytest.raises(ValueError, match="resource|bound"):
        module.validate_worker_inspection(info, mounts, "task13")


@pytest.mark.parametrize("tamper", [None, "dependencies", "knowledge"])
def test_preflight_checks_resource_hashes_before_docker(tmp_path, monkeypatch, tamper):
    import json
    from types import SimpleNamespace

    from evals.runners.manifest import ROOT, file_hash

    module = runtime()
    dependencies = tmp_path / "dependencies"
    dependencies.mkdir()
    (dependencies / "module.py").write_text("locked dependency")
    lock_hash = file_hash(ROOT / "services/backend/uv.lock")
    (dependencies / "task13_dependencies.json").write_text(
        json.dumps(
            {
                "platform": "linux-amd64",
                "python_version": "3.12.14",
                "lock_sha256": lock_hash,
                "tree_sha256": module.dependency_tree_hash(dependencies),
            }
        )
    )
    knowledge = tmp_path / "knowledge"
    knowledge.mkdir()
    (knowledge / "snapshot").write_text("frozen knowledge")
    options = {
        "source_dir": str(tmp_path / "source"),
        "source_commit": "a" * 40,
        "image_id": "sha256:" + "b" * 64,
        "network": "task13",
        "dependencies_dir": str(dependencies),
        "dependencies_lock_sha256": lock_hash,
        "knowledge_dir": str(knowledge),
        "knowledge_sha256": module.dependency_tree_hash(knowledge),
        "budget_dir": str(tmp_path / "budget"),
        "output_dir": str(tmp_path / "output"),
        "phase": "development",
    }
    controller = {"source_commit": "a" * 40, "budget_cny": 100, "dev_budget_cny": 15}
    monkeypatch.setenv("DEEPSEEK_API_KEY", "synthetic-test-credential")
    monkeypatch.setattr(module, "_validate_source", lambda root, commit: None)
    calls = []

    def inspect(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(module.subprocess, "run", inspect)
    if tamper == "dependencies":
        (dependencies / "module.py").write_text("changed dependency")
    elif tamper == "knowledge":
        (knowledge / "snapshot").write_text("changed knowledge")
    if tamper:
        with pytest.raises(ValueError, match="dependencies|knowledge"):
            module.preflight_runtime(options, controller)
        assert calls == []
    else:
        module.preflight_runtime(options, controller)
        assert calls == [
            ["docker", "image", "inspect", options["image_id"]],
            ["docker", "network", "inspect", "task13"],
        ]
        assert (tmp_path / "budget/campaign.sqlite").is_file()


@pytest.mark.asyncio
async def test_verification_request_uses_original_validator_entrypoint_only(
    tmp_path, monkeypatch
):
    from evals.contracts import canonical_hash
    from evals.tests.test_verification_observations import approved_fixture

    module = runtime()
    adapter = importlib.import_module("evals.adapters.verification_worker")
    state, _ = approved_fixture()
    receipt = {
        "status": "verified",
        "source": "original_product_database",
        "state_sha256": canonical_hash(state),
        "approval_sha256": canonical_hash(state["approval"]),
        "plan_sha256": state["approved_plan_sha256"],
        "plan_version": state["approved_plan_version"],
    }
    payload = {
        "schema_version": "task13-verification-worker-v1",
        "request_id": "a" * 32,
        "namespace": "b" * 32,
        "case_id": "ait-" + "0" * 24,
        "agent_sha256": "c" * 64,
        "source_state_sha256": canonical_hash(state),
        "approved_plan_sha256": state["approved_plan_sha256"],
        "approval_receipt": receipt,
        "approval_receipt_sha256": canonical_hash(receipt),
        "approved_state": state,
        "source_resources": {
            "database_name": "task13_" + "d" * 32,
            "index_name": "security-events-task13-" + "d" * 32,
        },
        "verification_enabled": True,
        "observations": {},
    }
    assert hasattr(module, "_worker_request"), (
        "the bootstrap must validate the verification request separately"
    )
    request = module._worker_request(payload)
    assert isinstance(request, adapter.VerificationWorkerRequest)
    seen = []

    async def verify(current, agent_dir):
        seen.append((current, agent_dir))
        return {"status": "completed", "model_ledger": []}

    monkeypatch.setattr(adapter, "run_verification", verify)
    assert await module._invoke_adapter(request, tmp_path) == {
        "status": "completed",
        "model_ledger": [],
    }
    assert seen == [(request, tmp_path)]
    payload["condition"] = "success"
    with pytest.raises(ValueError):
        module._worker_request(payload)


@pytest.mark.asyncio
async def test_verification_wrapper_rejects_model_calls_and_diagnosis_requests(
    monkeypatch,
):
    module = runtime()
    calls = []
    result = {"status": "completed", "model_ledger": []}

    async def container(spec, agent_dir, options):
        calls.append((spec, agent_dir, options))
        return result

    monkeypatch.setattr(module, "run_container", container)
    spec = {"schema_version": "task13-verification-worker-v1"}
    assert await module.run_verification_container(spec, Path("agent"), {}) == result
    assert len(calls) == 1
    with pytest.raises(ValueError, match="schema"):
        await module.run_verification_container({"group": "B3"}, Path("agent"), {})
    assert len(calls) == 1
    result["model_ledger"] = [{"request_id": "forbidden-model-call"}]
    with pytest.raises(ValueError, match="model"):
        await module.run_verification_container(spec, Path("agent"), {})


@pytest.mark.asyncio
async def test_worker_receives_the_validated_source_commit_in_environment(
    tmp_path, monkeypatch
):
    import json

    from evals.contracts import WorkerRunSpec

    module = runtime()
    source = tmp_path / "source"
    source.mkdir()
    dependencies = tmp_path / "dependencies"
    dependencies.mkdir()
    for name in [
        "mcp",
        "langgraph",
        "langchain_openai",
        "fastembed",
        "pydantic",
        "sqlalchemy",
        "httpx",
    ]:
        (dependencies / name).mkdir()
    lock_hash = "b" * 64
    (dependencies / "task13_dependencies.json").write_text(
        json.dumps(
            {
                "platform": "linux-amd64",
                "python_version": "3.12.14",
                "lock_sha256": lock_hash,
                "tree_sha256": module.dependency_tree_hash(dependencies),
            }
        ),
        encoding="utf-8",
    )
    knowledge = tmp_path / "knowledge"
    knowledge.mkdir()
    agent = tmp_path / "agent"
    agent.mkdir()
    (agent / "events.jsonl").write_text("{}\n", encoding="utf-8")
    options = {
        "source_dir": str(source),
        "source_commit": "a" * 40,
        "image_id": "sha256:" + "c" * 64,
        "network": "task13",
        "dependencies_dir": str(dependencies),
        "dependencies_lock_sha256": lock_hash,
        "knowledge_dir": str(knowledge),
        "knowledge_sha256": module.dependency_tree_hash(knowledge),
        "budget_dir": str(tmp_path / "budget"),
        "output_dir": str(tmp_path / "output"),
        "phase": "development",
    }
    spec = WorkerRunSpec(
        run_id="run-001", case_id="ait-" + "0" * 24, group="B3", config_sha256="d" * 64
    )
    monkeypatch.setattr(module, "_validate_source", lambda root, commit: None)
    received_commits = []

    class LaunchIntercepted(Exception):
        pass

    async def intercept_launch(*args, **kwargs):
        received_commits.append(kwargs["env"].get("TASK13_SOURCE_COMMIT"))
        raise LaunchIntercepted()

    monkeypatch.setattr(module.asyncio, "create_subprocess_exec", intercept_launch)
    with pytest.raises(LaunchIntercepted):
        await module.run_container(spec.model_dump(mode="json"), agent, options)
    assert received_commits == [options["source_commit"]]
