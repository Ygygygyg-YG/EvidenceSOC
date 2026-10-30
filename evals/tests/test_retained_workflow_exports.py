"""Working-tree export regressions; these are not committed-source G4 evidence."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from evals.tests.test_verification_plan import cases, fixture_source
from scripts.task13_worker_runtime import EXPORT_PATHS


def test_source_review_dependencies_work_with_only_worker_export_paths(tmp_path):
    """A worker must never need the controller or its condition/truth modules."""
    repository = Path(__file__).resolve().parents[2]
    exported = tmp_path / "exported-working-tree"
    assert EXPORT_PATHS == [
        "services/backend/src",
        "evals/contracts.py",
        "evals/e_planning.py",
        "evals/additional_source_selection.py",
        "evals/adapters",
        "scripts/dedale_task12_runtime.py",
        "scripts/task13_worker_runtime.py",
    ]
    for relative in EXPORT_PATHS:
        source, destination = repository / relative, exported / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(
                source, destination, ignore=shutil.ignore_patterns("__pycache__")
            )
        else:
            shutil.copyfile(source, destination)
    state = fixture_source()["state"]
    state.update(status="awaiting_approval", approval=None)
    input_path = tmp_path / "synthetic-state.json"
    input_path.write_text(
        json.dumps({"case": cases()[0], "state": state}), encoding="utf-8"
    )
    # Isolated mode removes the repository and PYTHONPATH. The import fence also
    # catches accidental access through an installed editable-package finder.
    program = r"""
import asyncio
import importlib.abc
import json
import os
import sys
from contextlib import asynccontextmanager
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

root, input_path = map(Path, sys.argv[1:])
sys.path[:0] = [str(root), str(root / "services/backend/src")]

class ControllerFence(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.startswith("evals.") and not (
            fullname in {"evals.contracts", "evals.e_planning", "evals.adapters"}
            or fullname.startswith("evals.adapters.")
        ):
            raise AssertionError("worker attempted controller import: " + fullname)

sys.meta_path.insert(0, ControllerFence())
from evals.adapters import verification_worker as worker
from evals.adapters import analysis_package, e_planning_worker, e_planning_review

assert Path(worker.__file__).is_relative_to(root)
for module in (analysis_package, e_planning_worker, e_planning_review):
    assert Path(module.__file__).is_relative_to(root)
data = json.loads(input_path.read_text(encoding="utf-8"))
agent, output = root / "agent", root / "output"
agent.mkdir()
output.mkdir()
events = b'{}\n'
(agent / "events.jsonl").write_bytes(events)
request = worker.SourceReviewRequest(
    request_id="a" * 32, namespace="b" * 32,
    case_id=data["case"]["case_id"], dataset="ait",
    agent_sha256=sha256(events).hexdigest(), source_commit="c" * 40,
    source_resources={"database_name": "task13_" + "d" * 32,
                      "index_name": "security-events-task13-" + "d" * 32},
    incident_id=data["state"]["incident_id"], operation="read_packet",
)
os.environ.pop("TASK13_WORKER_NONCE", None)
try:
    asyncio.run(worker.run_source_review(request, agent))
except PermissionError as error:
    assert "inspected bound worker" in str(error)
else:
    raise AssertionError("source review bypassed inspected-worker guard")

from evals.adapters import retained_workflow
assert Path(retained_workflow.__file__).is_relative_to(root)
assert not hasattr(retained_workflow, "CONDITIONS")
assert not hasattr(retained_workflow, "_measurements")

class Workflow:
    services = SimpleNamespace(_sessions=None)
    async def get_state(self, incident_id):
        assert incident_id == data["state"]["incident_id"]
        return data["state"]

@asynccontextmanager
async def synthetic_checkpoint(reference, *, model=None):
    assert model is None
    assert reference["source_commit"] == request.source_commit
    yield Workflow()

class Ledger:
    def __init__(self, sessions):
        pass
    def calls(self, *args):
        return []

# Only storage and the host PID are synthetic; real input/phase/commit/nonce,
# packet sealing and immutable artifact checks still execute.
retained_workflow.open_retained_workflow = synthetic_checkpoint
worker.Ledger = Ledger
worker.os = SimpleNamespace(environ=os.environ, getpid=lambda: 1)
os.environ.update(TASK13_WORKER_NONCE="synthetic-export-test-only",
                  TASK13_PHASE="verification", TASK13_SOURCE_COMMIT=request.source_commit,
                  TASK13_OUTPUT_DIR=str(output))
result = asyncio.run(worker.run_source_review(request, agent))
assert result["status"] == "completed", result
assert result["approval_packet"]["decision"] is None
assert result["model_ledger"] == []
assert result["tool_ledger"] == []
assert json.loads((output / "source-review-state.json").read_text(encoding="utf-8")) == data["state"]
assert json.loads((output / "approval-packet.json").read_text(encoding="utf-8")) == result["approval_packet"]
from evals.adapters.artifacts import write_immutable_json
try:
    write_immutable_json(output / "approval-packet.json", {})
except FileExistsError:
    pass
else:
    raise AssertionError("immutable packet was overwritten")
print("working-tree export source-review dependency boundary passed")
"""
    environment = dict(os.environ)
    environment.pop("SSLKEYLOGFILE", None)
    completed = subprocess.run(
        [sys.executable, "-I", "-c", program, str(exported), str(input_path)],
        cwd=exported,
        env=environment,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert (
        "working-tree export source-review dependency boundary passed"
        in completed.stdout
    )
