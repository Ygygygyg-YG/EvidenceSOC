"""Private real native lease controls; no original context, SQL or services."""

import ast
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals.tests.test_timing_pool_recovery import synthetic_spec


def private_pool(tmp_path, monkeypatch):
    from scripts import task13_manual_recovery as compiler

    recovery, spec, journal = synthetic_spec(tmp_path, monkeypatch)
    children, roots = [], []
    for ordinal in (1, 2):
        base = tmp_path / ("SYNTHETIC-child-" + str(ordinal))
        host = base / "host-output"
        timing = host / "timing"
        for root in (base / "worker-output", base / "host-termination", host, timing):
            root.mkdir(parents=True, exist_ok=True)
            roots.append(root)
        children.append({"evidence_root": str(timing)})
    spec["controller_state_roots"].extend(str(root.resolve()) for root in roots)
    return compiler, recovery, spec, journal, {"children": children}


def test_live_owned_fences_and_host_locks_are_inert_only_with_capability(
    tmp_path, monkeypatch
):
    compiler, recovery, spec, _journal, pool = private_pool(tmp_path, monkeypatch)
    compiler.require_inert_outputs(pool)
    with recovery.manual_recovery_quiescence(spec) as lease:
        recovery._require_lease(lease)
        assert all(
            Path(child["evidence_root"]).joinpath(".pool-adoption-fence").is_dir()
            for child in pool["children"]
        )
        # This is the genuine old failure: the strict guard sees its own live
        # native locks, before any metadata execution or original SQL access.
        with pytest.raises(PermissionError, match="native execution output"):
            compiler.require_inert_outputs(pool)
        compiler.require_inert_outputs(pool, lease=lease)
    compiler.require_inert_outputs(pool)


def test_nested_timing_genesis_allows_only_verified_live_locks(tmp_path, monkeypatch):
    compiler, recovery, spec, _journal, pool = private_pool(tmp_path, monkeypatch)
    for child in pool["children"]:
        timing = Path(child["evidence_root"])
        (timing.parent / "host-binding.json").write_bytes(b"{}")
        (timing / "registration.json").write_bytes(b"{}")
        events = timing / "events"
        events.mkdir()
        (events / ("00000000-" + "a" * 64 + ".json")).write_bytes(b"{}")
        spec["controller_state_roots"].append(str(events.resolve()))
    compiler.require_inert_outputs(pool)
    with recovery.manual_recovery_quiescence(spec) as lease:
        compiler.require_inert_outputs(pool, lease=lease)
    compiler.require_inert_outputs(pool)


def test_old_sealed_roots_may_legitimately_omit_writer_locks(tmp_path, monkeypatch):
    from evals.tests.test_source_epochs import additional_terminal

    compiler, recovery, spec, journal, pool = private_pool(tmp_path, monkeypatch)
    sealed = additional_terminal(journal.path.parent, completed=True)
    nested = sealed / "worker.controller"
    spec["controller_state_roots"].extend(
        (str(sealed.resolve()), str(nested.resolve()))
    )
    before = {
        str(path): path.read_bytes() for path in sealed.rglob("*") if path.is_file()
    }
    with recovery.manual_recovery_quiescence(spec) as lease:
        for root in (sealed, nested):
            assert (root / ".pool-adoption-fence").is_dir()
            assert not (root / "host-writer.lock").exists()
        compiler.require_inert_outputs(pool, lease=lease)
    assert before == {
        str(path): path.read_bytes() for path in sealed.rglob("*") if path.is_file()
    }


def test_forged_and_stale_lease_are_rejected(tmp_path, monkeypatch):
    compiler, recovery, spec, _journal, pool = private_pool(tmp_path, monkeypatch)
    with recovery.manual_recovery_quiescence(spec) as lease:
        forged = recovery.RecoveryLease(
            deepcopy(lease.spec), lease.nonce, dict(lease.owned), list(lease.journals)
        )
        for bad in (
            object(),
            SimpleNamespace(spec=lease.spec, owned=lease.owned),
            forged,
        ):
            with pytest.raises(PermissionError, match="lease"):
                compiler.require_inert_outputs(pool, lease=bad)
    with pytest.raises(PermissionError, match="lease"):
        compiler.require_inert_outputs(pool, lease=lease)


def test_foreign_live_lease_cannot_authorize_an_uncovered_pool(tmp_path, monkeypatch):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir()
    second.mkdir()
    compiler, _recovery, _spec, _journal, pool = private_pool(first, monkeypatch)
    _, recovery, spec, _journal, _foreign = private_pool(second, monkeypatch)
    with (
        recovery.manual_recovery_quiescence(spec) as foreign,
        pytest.raises(PermissionError),
    ):
        compiler.require_inert_outputs(pool, lease=foreign)


@pytest.mark.parametrize(
    "damage",
    [
        "fence_inode",
        "nonempty_fence",
        "lock_bytes",
        "lock_bytes_and_owned",
        "spec",
        "foreign_owned_entry",
    ],
)
def test_live_capability_damage_is_rejected_and_restored(tmp_path, monkeypatch, damage):
    compiler, recovery, spec, _journal, pool = private_pool(tmp_path, monkeypatch)
    timing = Path(pool["children"][0]["evidence_root"])
    with recovery.manual_recovery_quiescence(spec) as lease:
        fence, lock = timing / ".pool-adoption-fence", timing / "host-writer.lock"
        original_raw = lock.read_bytes()
        if damage == "fence_inode":
            held = timing / "held-original-fence"
            fence.rename(held)
            fence.mkdir()
        elif damage == "nonempty_fence":
            (fence / "foreign").write_bytes(b"foreign")
        elif damage in {"lock_bytes", "lock_bytes_and_owned"}:
            lock.write_bytes(b"foreign owner")
            if damage == "lock_bytes_and_owned":
                lease.owned[lock] = b"foreign owner"
        elif damage == "spec":
            original_scope = lease.spec["expected_scope"]
            lease.spec["expected_scope"] = {**original_scope, "sha256": "0" * 64}
        else:
            foreign = timing / "foreign-owned-output"
            foreign.write_bytes(b"foreign")
            lease.owned[foreign] = b"foreign"
        try:
            with pytest.raises(PermissionError):
                compiler.require_inert_outputs(pool, lease=lease)
        finally:
            if damage == "fence_inode":
                fence.rmdir()
                held.rename(fence)
            elif damage == "nonempty_fence":
                (fence / "foreign").unlink()
            elif damage in {"lock_bytes", "lock_bytes_and_owned"}:
                lock.write_bytes(original_raw)
                lease.owned[lock] = original_raw
            elif damage == "spec":
                lease.spec["expected_scope"] = original_scope
            else:
                lease.owned.pop(foreign)
                foreign.unlink()
        compiler.require_inert_outputs(pool, lease=lease)


@pytest.mark.parametrize(
    "location", ["worker", "termination", "host", "timing", "execution_event"]
)
def test_own_lease_never_hides_foreign_outputs(tmp_path, monkeypatch, location):
    compiler, recovery, spec, _journal, pool = private_pool(tmp_path, monkeypatch)
    timing = Path(pool["children"][1]["evidence_root"])
    host, base = timing.parent, timing.parent.parent
    parent = {
        "worker": base / "worker-output",
        "termination": base / "host-termination",
        "host": host,
        "timing": timing,
        "execution_event": timing / "events",
    }[location]
    parent.mkdir(exist_ok=True)
    with recovery.manual_recovery_quiescence(spec) as lease:
        target = parent / (
            "00000001-" + "b" * 64 + ".json"
            if location == "execution_event"
            else "foreign-execution.json"
        )
        target.write_bytes(b"{}")
        try:
            with pytest.raises(PermissionError):
                compiler.require_inert_outputs(pool, lease=lease)
        finally:
            target.unlink()
        compiler.require_inert_outputs(pool, lease=lease)


def test_live_lease_owned_map_cannot_omit_current_pool_locks(tmp_path, monkeypatch):
    compiler, recovery, spec, _journal, pool = private_pool(tmp_path, monkeypatch)
    path = Path(pool["children"][0]["evidence_root"]) / "host-writer.lock"
    with recovery.manual_recovery_quiescence(spec) as lease:
        owner = lease.owned.pop(path)
        try:
            with pytest.raises(PermissionError):
                compiler.require_inert_outputs(pool, lease=lease)
        finally:
            lease.owned[path] = owner
        compiler.require_inert_outputs(pool, lease=lease)


def test_parent_genesis_default_lock_stays_fenced_until_lease_exit(
    tmp_path, monkeypatch
):
    from evals.timing_pool_controller import PoolJournal

    _compiler, recovery, spec, _journal, _pool = private_pool(tmp_path, monkeypatch)
    root = tmp_path / "SYNTHETIC-new-parent"
    root.mkdir()
    spec["controller_state_roots"].append(str(root.resolve()))
    kwargs = {
        "pool_sha256": "c" * 64,
        "attempts": [f"new-{i}" for i in range(6)],
        "imported_trial_id": "private-import",
        "now": datetime.now(UTC),
    }
    target = root / "pool-journal.jsonl"
    with recovery.manual_recovery_quiescence(spec):
        with pytest.raises(PermissionError, match="fence"):
            PoolJournal.prepare(target, **kwargs)
        assert not target.exists()
    journal = PoolJournal.prepare(target, **kwargs)
    assert len(journal._events()) == 1


def test_adopt_passes_capability_only_inside_lease_and_parent_stays_outside():
    from scripts import task13_manual_recovery as compiler

    module = ast.parse(Path(compiler.__file__).read_text(encoding="utf8"))
    adopt = next(
        node
        for node in module.body
        if isinstance(node, ast.FunctionDef) and node.name == "adopt"
    )
    lease_block = next(
        node
        for node in adopt.body
        if isinstance(node, ast.With)
        and any(
            isinstance(item.context_expr, ast.Call)
            and isinstance(item.context_expr.func, ast.Name)
            and item.context_expr.func.id == "manual_recovery_quiescence"
            for item in node.items
        )
    )
    protected = [
        node
        for node in ast.walk(lease_block)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "require_inert_outputs"
    ]
    assert len(protected) == 1 and len(protected[0].keywords) == 1
    assert (
        protected[0].keywords[0].arg == "lease"
        and isinstance(protected[0].keywords[0].value, ast.Name)
        and protected[0].keywords[0].value.id == "lease"
    )
    all_guards = [
        node
        for node in ast.walk(adopt)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "require_inert_outputs"
    ]
    assert len(all_guards) == 2 and sum(bool(call.keywords) for call in all_guards) == 1
    prepare = next(
        node
        for node in ast.walk(adopt)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "PoolJournal"
        and node.func.attr == "prepare"
    )
    assert prepare.lineno > lease_block.end_lineno
    assert not any(keyword.arg == "_adoption" for keyword in prepare.keywords)
