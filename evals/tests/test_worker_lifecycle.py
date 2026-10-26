"""Host lifecycle evidence with synthetic processes; never runs Docker."""

import asyncio
import json
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest


class Process:
    def __init__(self, returncode=None):
        self.returncode = returncode
        self.waits = 0

    async def wait(self):
        self.waits += 1
        self.returncode = 137


def values():
    return {
        "process": Process(),
        "name": "task13-worker-" + "a" * 32,
        "nonce": "a" * 32,
        "container_id": "b" * 64,
        "request_sha256": "c" * 64,
        "source_commit": "d" * 40,
        "environment": {},
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("returncode", [None, 0])
async def test_host_captures_exit_and_actual_daemon_absence(
    tmp_path, monkeypatch, returncode
):
    from evals import worker_lifecycle as m

    called = []

    async def spawn(*argv, **kwargs):
        called.append(argv)
        return SimpleNamespace(returncode=0, communicate=empty)

    async def empty():
        return b"", b""

    monkeypatch.setattr(m.asyncio, "create_subprocess_exec", spawn)
    args = values()
    args["process"].returncode = returncode
    receipt = await m.capture_worker_termination(**args, receipt_dir=tmp_path)
    assert receipt["status"] == "verified"
    assert receipt["host_process_exited"] and receipt["container_absent"]
    assert receipt["process_returncode"] == (137 if returncode is None else 0)
    assert any(command[1:3] == ("container", "ls") for command in called)
    assert any(command[1:3] == ("rm", "-f") for command in called) == (
        returncode is None
    )
    raw = Path(receipt["receipt_path"]).read_bytes()
    assert sha256(raw).hexdigest() == receipt["receipt_binding_sha256"]


@pytest.mark.asyncio
@pytest.mark.parametrize("daemon_code,present", [(1, False), (0, True)])
async def test_daemon_error_or_existing_container_never_proves_termination(
    tmp_path,
    monkeypatch,
    daemon_code,
    present,
):
    from evals import worker_lifecycle as m

    async def empty():
        return (b"b" * 64 + b"\n" if present else b"", b"synthetic daemon error")

    async def spawn(*argv, **kwargs):
        return SimpleNamespace(returncode=daemon_code, communicate=empty)

    monkeypatch.setattr(m.asyncio, "create_subprocess_exec", spawn)
    args = values()
    args["process"].returncode = 0
    receipt = await m.capture_worker_termination(**args, receipt_dir=tmp_path)
    assert receipt["status"] == "unknown"
    assert receipt["container_absent"] is False


@pytest.mark.asyncio
async def test_refuses_an_unowned_container_target(tmp_path):
    from evals import worker_lifecycle as m

    args = values()
    args["name"] = "evidencesoc-postgres-1"
    with pytest.raises(ValueError, match="owned"):
        await m.capture_worker_termination(**args, receipt_dir=tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.asyncio
async def test_verifier_reads_host_evidence_and_rejects_missing_or_tampered_receipt(
    tmp_path, monkeypatch
):
    from evals import worker_lifecycle as m
    from evals.contracts import canonical_hash

    async def empty():
        return b"", b""

    async def spawn(*argv, **kwargs):
        return SimpleNamespace(returncode=0, communicate=empty)

    monkeypatch.setattr(m.asyncio, "create_subprocess_exec", spawn)
    request = {"request_id": "e" * 32}
    verifier = m.HostWorkerLifecycleVerifier(tmp_path)
    assert verifier(request, timed_out=True)["status"] == "unknown"
    args = values()
    args["request_sha256"] = canonical_hash(request)
    receipt = await m.capture_worker_termination(**args, receipt_dir=tmp_path)
    checked = verifier(request, timed_out=True)
    assert checked["status"] == "verified"
    assert checked["receipt_binding_sha256"] == receipt["receipt_binding_sha256"]
    path = Path(receipt["receipt_path"])
    original = json.loads(path.read_text(encoding="utf-8"))
    original["container_absent"] = False
    path.write_text(json.dumps(original), encoding="utf-8")
    assert verifier(request, timed_out=False)["status"] == "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize("cancelled", [False, True])
async def test_runtime_records_host_termination_after_return_or_cancellation(
    tmp_path, monkeypatch, cancelled
):
    from evals.worker_lifecycle import HostWorkerLifecycleVerifier
    from scripts import task13_worker_runtime as runtime

    dependencies = tmp_path / "deps"
    for name in (
        "mcp",
        "langgraph",
        "langchain_openai",
        "fastembed",
        "pydantic",
        "sqlalchemy",
        "httpx",
    ):
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
    events = b"{}\n"
    (agent / "events.jsonl").write_bytes(events)
    spec = {
        "schema_version": "task13-verification-worker-v1",
        "case_id": "ait-" + "0" * 24,
        "request_id": "e" * 32,
    }
    monkeypatch.setattr(
        runtime,
        "_worker_request",
        lambda value: SimpleNamespace(
            schema_version=spec["schema_version"],
            agent_sha256=sha256(events).hexdigest(),
        ),
    )
    monkeypatch.setattr(runtime, "_validate_source", lambda *args: None)
    monkeypatch.setattr(runtime, "dependency_tree_hash", lambda path: "b" * 64)
    monkeypatch.setattr(
        runtime, "validate_worker_binding", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        runtime,
        "validate_worker_inspection",
        lambda *args: {
            "image_id": "sha256:" + "c" * 64,
            "container_id": "b" * 64,
        },
    )
    communicating = asyncio.Event()
    never = asyncio.Event()

    class Child:
        returncode = None

        def __init__(self, kind):
            self.kind = kind
            self.stderr = self.stdin = self

        async def readline(self):
            return (
                runtime.PROBE_PREFIX.encode()
                + json.dumps({"python_version": "3.12.14"}).encode()
            )

        async def communicate(self):
            if self.kind == "run":
                communicating.set()
                if cancelled:
                    await never.wait()
                self.returncode = 0
                return b'{"model_ledger":[]}', b""
            self.returncode = 0
            return (b"[{}]" if self.kind == "inspect" else b""), b""

        async def wait(self):
            self.returncode = 137 if self.returncode is None else self.returncode
            return self.returncode

        def write(self, data):
            pass

        async def drain(self):
            pass

        def close(self):
            pass

    async def spawn(*argv, **kwargs):
        assert "DEEPSEEK_API_KEY" not in kwargs["env"]
        return Child(argv[1])

    monkeypatch.setattr(runtime.asyncio, "create_subprocess_exec", spawn)
    receipt_dir = tmp_path / "host-receipts"
    options = {
        "source_dir": str(tmp_path / "source"),
        "source_commit": "d" * 40,
        "dependencies_dir": str(dependencies),
        "dependencies_lock_sha256": "a" * 64,
        "knowledge_dir": str(tmp_path / "knowledge"),
        "knowledge_sha256": "b" * 64,
        "budget_dir": str(tmp_path / "budget"),
        "output_dir": str(tmp_path / "output"),
        "image_id": "sha256:" + "c" * 64,
        "network": "synthetic",
        "phase": "verification",
        "host_termination_dir": str(receipt_dir),
    }
    task = asyncio.create_task(runtime.run_container(spec, agent, options))
    if cancelled:
        await communicating.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    else:
        await task
    evidence = HostWorkerLifecycleVerifier(receipt_dir)(spec, timed_out=cancelled)
    assert evidence["status"] == "verified"
    assert evidence["container_id"] == "b" * 64
    assert evidence["source_commit"] == "d" * 40
