"""Read-only regression against the genuine stopped original pool."""

import sys
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

import pytest

from evals import timing_pool as pool

ORIGINAL = Path(
    r"D:\传智杯\data\task13\supplements\task13-repair-202610-v2\development\timing-pool-candidate-20261101-2f360b77"
)
ROOT = ORIGINAL / "pool-059220946fb6436786ec3566765983f3-child-1/host-output/timing"


@pytest.fixture
def original():
    if not ROOT.is_dir():
        pytest.skip("genuine original stopped pool is unavailable")
    view = pool._view(ROOT)
    host = pool._json(ROOT.parent / "host-binding.json")
    return view, host, pool._load_host_inputs(view, host)


def test_genuine_old_pool_uses_its_actual_frozen_host_without_writes(
    original, monkeypatch
):
    from scripts import task13_e_trial as current

    view, host, inputs = original
    paths = list(ORIGINAL.rglob("*"))
    paths += [Path(inputs["runtime_options"]["budget_dir"]) / "campaign.sqlite"]
    before = {str(p): sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()}
    current_file = current.__file__
    current_globals = current.ETrialController._scope.__globals__
    modules = set(sys.modules)

    def forbidden(*args, **kwargs):
        raise AssertionError("historical read invoked a current constructor or scope")

    monkeypatch.setattr(current.ETrialController, "__init__", forbidden)
    context = pool._validate_host_semantics(view, host, inputs)
    reader = context["reader"]
    frozen = Path(inputs["scope_packet"]["source_tree"]) / "scripts/task13_e_trial.py"
    assert type(reader) is not current.ETrialController
    assert Path(reader._scope.__globals__["__file__"]) == frozen
    assert Path(reader._scope.__code__.co_filename) == frozen
    assert reader._requests[0].source_commit == view.registration["source_commit"]
    assert (
        reader._requests[0].model_identity_binding.model_epoch_id
        == context["model"]["model_epoch_id"]
    )
    assert (
        sum(claim["status"] == "started" for claim in context["claims"].values()) == 1
    )
    assert not hasattr(reader, "_free")  # The native constructor was never run.
    assert current.__file__ == current_file
    assert current_globals["__file__"] == current_file
    assert not any(
        name.startswith("_task13_historical_host_")
        for name in set(sys.modules) - modules
    )
    assert before == {
        str(p): sha256(p.read_bytes()).hexdigest() for p in paths if p.is_file()
    }
    assert {p for p in ORIGINAL.rglob("*") if p.is_file()} == {
        Path(p) for p in before if Path(p).is_relative_to(ORIGINAL)
    }


def test_genuine_original_pool_rejects_unverified_readiness(original):
    view, host, inputs = original
    bad = deepcopy(inputs)
    bad["readiness"]["status"] = "unverified"
    with pytest.raises(PermissionError):
        pool._validate_host_semantics(view, host, bad)


@pytest.mark.parametrize("registry", ["source_epochs", "model_identities"])
def test_original_sql_identity_authentication_precedes_old_code(
    original, monkeypatch, registry
):
    from importlib import import_module

    from evals import timing_pool_history as history

    def forbidden(*args, **kwargs):
        raise AssertionError("historical code executed before SQL authentication")

    def unregistered(*args, **kwargs):
        raise ValueError("invented original registry identity")

    monkeypatch.setattr(history, "exec", forbidden, raising=False)
    name = (
        "require_registered_epoch"
        if registry == "source_epochs"
        else "require_registered_model_identity"
    )
    monkeypatch.setattr(import_module("evals.adapters." + registry), name, unregistered)
    with pytest.raises(ValueError, match="invented original registry identity"):
        pool._validate_host_semantics(*original)


def test_native_authority_semantics_precede_old_code(original, monkeypatch):
    from evals import timing_pool_history as history
    from evals.adapters import e_planning_journal

    def forbidden(*args, **kwargs):
        raise AssertionError("historical code executed before native authority parse")

    def invalid(*args, **kwargs):
        raise ValueError("native planning authority is invalid")

    monkeypatch.setattr(history, "exec", forbidden, raising=False)
    monkeypatch.setattr(e_planning_journal, "parse_authority", invalid)
    with pytest.raises(ValueError, match="native planning authority is invalid"):
        pool._validate_host_semantics(*original)


@pytest.mark.parametrize(
    "target",
    ["script", "pool-host", "controller-manifest", "worker-receipt", "worker-source"],
)
def test_tampered_original_bytes_are_rejected_before_execution(
    original, monkeypatch, target
):
    from evals import timing_pool_history as history

    view, host, inputs = original
    packet = inputs["scope_packet"]
    targets = {
        "script": Path(packet["source_tree"]) / "scripts/task13_e_trial.py",
        "pool-host": Path(packet["source_tree"]) / "evals/timing_pool.py",
        "controller-manifest": Path(packet["controller_manifest"]["path"]),
        "worker-receipt": Path(packet["source_receipt"]["path"]),
        "worker-source": Path(inputs["runtime_options"]["source_dir"])
        / "evals/adapters/planning_analysis.py",
    }
    native = Path.read_bytes

    def read(path):
        raw = native(path)
        return raw + b"\n# tampered" if path == targets[target] else raw

    def forbidden(*args, **kwargs):
        raise AssertionError("historical code executed before raw authentication")

    monkeypatch.setattr(Path, "read_bytes", read)
    monkeypatch.setattr(history, "exec", forbidden, raising=False)
    with pytest.raises(PermissionError, match="bytes differ|raw pin differs"):
        pool._validate_host_semantics(view, host, inputs)


def test_only_native_read_methods_are_invoked(original, monkeypatch):
    from evals import timing_pool_history as history

    original_loader = history.historical_controller_type

    def forbidden(*args, **kwargs):
        raise AssertionError("historical reader called a mutation-capable operation")

    def load(*args):
        cls = original_loader(*args)
        for name in (
            "__init__",
            "_preflight",
            "_campaign",
            "prepare",
            "plan",
            "read",
            "decision",
            "dispatch",
            "resume",
            "_write",
            "_save",
        ):
            monkeypatch.setattr(cls, name, forbidden, raising=False)
        return cls

    monkeypatch.setattr(history, "historical_controller_type", load)
    assert pool._validate_host_semantics(*original)["claims"]


def test_current_v2_never_selects_historical_code_or_weakens_scope(
    original, monkeypatch
):
    from evals import timing_pool_history as history
    from scripts.task13_e_trial import ETrialController

    view, host, inputs = original
    inputs = deepcopy(inputs)
    inputs["pool_authority"]["schema_version"] = pool.RECOVERY_REGISTRATION_SCHEMA

    def forbidden(*args, **kwargs):
        raise AssertionError("v2 must not execute historical code")

    monkeypatch.setattr(history, "exec", forbidden, raising=False)
    assert (
        history.historical_controller_type(view, host, inputs, {}) is ETrialController
    )
    # The current native scope body remains the exact repository implementation.
    assert (
        Path(ETrialController._scope.__code__.co_filename).resolve()
        == Path(__file__).resolve().parents[2] / "scripts/task13_e_trial.py"
    )

    def current_freeze_failure(self):
        raise PermissionError("pool host implementation is not frozen")

    monkeypatch.setattr(ETrialController, "_scope", current_freeze_failure)
    with pytest.raises(PermissionError, match="pool host implementation is not frozen"):
        pool._validate_host_semantics(view, host, inputs)


@pytest.mark.parametrize("kind", ["link", "missing"])
def test_historical_script_path_is_checked_before_exec(original, monkeypatch, kind):
    from evals import timing_pool_history as history

    view, host, inputs = original
    script = Path(inputs["scope_packet"]["source_tree"]) / "scripts/task13_e_trial.py"

    def forbidden(*args, **kwargs):
        raise AssertionError("historical code executed before path authentication")

    monkeypatch.setattr(history, "exec", forbidden, raising=False)
    if kind == "link":
        native = Path.is_symlink
        monkeypatch.setattr(Path, "is_symlink", lambda p: p == script or native(p))
        expected = PermissionError
    else:
        native = Path.lstat

        def lstat(path, *args, **kwargs):
            if path == script:
                raise FileNotFoundError("original historical script is missing")
            return native(path, *args, **kwargs)

        monkeypatch.setattr(Path, "lstat", lstat)
        expected = FileNotFoundError
    with pytest.raises(expected):
        pool._validate_host_semantics(view, host, inputs)


@pytest.mark.parametrize(
    "kind", ["duplicate-relative", "mixed-root", "invented-source-hash"]
)
def test_altered_source_map_cannot_select_historical_reader(
    original, monkeypatch, kind
):
    from evals import timing_pool_history as history

    view, host, inputs = deepcopy(original)
    files = view.registration["source_files"]
    script = Path(inputs["scope_packet"]["source_tree"]) / "scripts/task13_e_trial.py"
    digest = files[str(script)]
    if kind == "duplicate-relative":
        files[str(script).replace("\\", "/")] = digest
    elif kind == "mixed-root":
        files[
            str(Path(__file__).resolve().parents[2] / "scripts/task13_e_trial.py")
        ] = digest
    else:
        files[str(script)] = "0" * 64
    inputs["timing_registration"] = view.registration

    def forbidden(*args, **kwargs):
        raise AssertionError("historical code executed for invented source mapping")

    monkeypatch.setattr(history, "exec", forbidden, raising=False)
    with pytest.raises((PermissionError, ValueError)):
        pool._validate_host_semantics(view, host, inputs)
