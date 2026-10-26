"""Controller-only proof that its inspected worker process and container ended.

This does not establish PostgreSQL/index cleanup, approval or worker validity.
Only the host runtime calls capture; a worker result is never accepted as proof.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from evals.contracts import canonical_hash

SCHEMA = "task13-host-worker-termination-v1"


def _safe_path(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute lifecycle evidence path required")
    for part in (path, *path.parents):
        if part.is_symlink() or part.is_junction():
            raise ValueError("lifecycle evidence links are forbidden")
    return path


async def _docker(arguments, environment):
    command = ["docker", *arguments]
    record = {"argv": command, "returncode": None}
    try:
        child = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
        try:
            stdout, stderr = await asyncio.wait_for(child.communicate(), timeout=15)
        except TimeoutError:
            child.kill()
            await child.wait()
            record["error_type"] = "TimeoutError"
            return record, None
        record.update(
            returncode=child.returncode,
            stdout_sha256=sha256(stdout).hexdigest(),
            stderr_sha256=sha256(stderr).hexdigest(),
        )
        return record, stdout
    except OSError as error:
        record["error_type"] = type(error).__name__
        return record, None


async def capture_worker_termination(
    *,
    process,
    name,
    nonce,
    container_id,
    request_sha256,
    source_commit,
    environment,
    receipt_dir,
):
    """Stop only the owned worker, query the daemon, then append a host receipt."""
    if (
        re.fullmatch(r"[0-9a-f]{32}", nonce or "") is None
        or name != "task13-worker-" + nonce
        or (
            container_id is not None
            and re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        )
        or re.fullmatch(r"[0-9a-f]{64}", request_sha256 or "") is None
        or re.fullmatch(r"[0-9a-f]{40}", source_commit or "") is None
    ):
        raise ValueError("owned worker identity required for termination")
    tick = time.monotonic()
    actions = []
    if process.returncode is None:
        stopped, _ = await _docker(["rm", "-f", name], environment)
        actions.append(stopped)
        try:
            await asyncio.wait_for(process.wait(), timeout=15)
        except TimeoutError:
            # Killing the Docker client is not proof that the container stopped.
            process.kill()
            await asyncio.wait_for(process.wait(), timeout=15)
    target = "id=" + container_id if container_id else "name=^/" + name + "$"
    listed, stdout = await _docker(
        [
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--filter",
            target,
            "--format",
            "{{.ID}}",
        ],
        environment,
    )
    actions.append(listed)
    absent = listed["returncode"] == 0 and stdout is not None and not stdout.strip()
    exited = process.returncode is not None
    receipt = {
        "schema_version": SCHEMA,
        "request_sha256": request_sha256,
        "status": "verified" if exited and absent and container_id else "unknown",
        "container_name": name,
        "container_id": container_id,
        "worker_nonce": nonce,
        "source_commit": source_commit,
        "host_process_exited": exited,
        "process_returncode": process.returncode,
        "container_absent": absent,
        "cleanup_duration_seconds": time.monotonic() - tick,
        "recorded_at": datetime.now(UTC).isoformat(),
        "host_actions": actions,
        "resource_cleanup": "not_established_by_container_termination",
    }
    raw = json.dumps(
        receipt, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    digest = sha256(raw).hexdigest()
    directory = _safe_path(Path(receipt_dir)) / request_sha256
    directory.mkdir(parents=True, exist_ok=True)
    _safe_path(directory)
    path = directory / (nonce + "-" + digest + ".json")
    with path.open("xb") as stream:
        stream.write(raw)
    return {**receipt, "receipt_path": str(path), "receipt_binding_sha256": digest}


class HostWorkerLifecycleVerifier:
    """Read host evidence after completion/cancellation; never starts a worker."""

    def __init__(self, receipt_dir):
        self.root = _safe_path(Path(receipt_dir))

    def __call__(self, request, *, timed_out):
        expected = canonical_hash(request)
        unknown = {
            "schema_version": SCHEMA,
            "request_sha256": expected,
            "status": "unknown",
            "container_id": None,
            "worker_nonce": None,
            "host_process_exited": False,
            "container_absent": False,
            "receipt_binding_sha256": None,
        }
        try:
            directory = _safe_path(self.root / expected)
            paths = list(directory.glob("*.json"))
            if len(paths) != 1:
                return unknown
            path = _safe_path(paths[0])
            raw = path.read_bytes()
            digest = sha256(raw).hexdigest()
            value = json.loads(raw)
            if (
                value.get("schema_version") != SCHEMA
                or value.get("request_sha256") != expected
                or value.get("status") != "verified"
                or value.get("host_process_exited") is not True
                or value.get("container_absent") is not True
                or type(value.get("process_returncode")) is not int
                or re.fullmatch(r"[0-9a-f]{64}", value.get("container_id") or "")
                is None
                or re.fullmatch(r"[0-9a-f]{32}", value.get("worker_nonce") or "")
                is None
                or value.get("container_name")
                != "task13-worker-" + value["worker_nonce"]
                or path.name != value["worker_nonce"] + "-" + digest + ".json"
                or not value.get("host_actions")
                or value["host_actions"][-1].get("returncode") != 0
                or value["host_actions"][-1].get("stdout_sha256")
                != sha256(b"").hexdigest()
            ):
                return unknown
            return {
                **value,
                "receipt_path": str(path),
                "receipt_binding_sha256": digest,
            }
        except (OSError, ValueError, TypeError, KeyError):
            return unknown
