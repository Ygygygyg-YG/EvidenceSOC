"""Offline fixture I/O namespace; never an execution authority or timing credit.

Only SQLite transport and historical lock directories are virtualized. All
native schema, hash, source, approval and ledger validators execute unchanged.
"""

import sqlite3
from contextlib import closing, contextmanager
from contextvars import ContextVar
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

_ISOLATED = ContextVar("pool_fixture_isolated_database_namespace", default=None)
_DATABASE_NAMESPACE = ContextVar("pool_fixture_database_transport", default=None)


def _database_path(database, uri):
    text = str(database)
    if uri and text.startswith("file:"):
        parsed = urlsplit(text)
        name = unquote(parsed.path)
        if len(name) > 2 and name[0] == "/" and name[2] == ":":
            name = name[1:]
        return Path(name).resolve(), parsed.query
    return Path(text).resolve(), ""


@contextmanager
def isolated_native_io(root, *, reopen_saved_copies=False):
    """Route every non-fixture database to a private copy, with no fallthrough."""
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    copies = root / "SQLITE-COPIES-NO-ACTUAL-CREDIT"
    copies.mkdir(exist_ok=reopen_saved_copies)
    locks = root / "VIRTUAL-HISTORICAL-LOCKS"
    locks.mkdir(exist_ok=reopen_saved_copies)
    original_connect = sqlite3.connect
    original_mkdir, original_rmdir, original_stat = Path.mkdir, Path.rmdir, Path.stat
    originals, redirected, lock_targets = {}, [], {}

    def connect(database, *args, **kwargs):
        if str(database) == ":memory:":
            return original_connect(database, *args, **kwargs)
        source, query = _database_path(database, kwargs.get("uri", False))
        if source.is_relative_to(root):
            return original_connect(database, *args, **kwargs)
        if not source.is_file():
            raise PermissionError("fixture cannot create an external database")
        if source not in originals:
            target = copies / (sha256(str(source).encode()).hexdigest() + ".sqlite")
            before = sha256(source.read_bytes()).hexdigest()
            # SQLite backup preserves a consistent image, including committed WAL.
            if reopen_saved_copies:
                if not target.is_file():
                    raise PermissionError("saved copy namespace is incomplete")
            else:
                with (
                    closing(
                        original_connect(source.as_uri() + "?mode=ro", uri=True)
                    ) as src,
                    closing(original_connect(target)) as dst,
                ):
                    src.backup(dst)
            originals[source] = (target, before)
        target = originals[source][0]
        redirected.append((source, target))
        if kwargs.get("uri", False):
            database = target.as_uri() + ("?" + query if query else "")
        else:
            database = target
        return original_connect(database, *args, **kwargs)

    def lock_target(path):
        # Path.resolve() itself calls Path.stat() for nonexistent Windows paths;
        # transport dispatch must therefore use lexical normalization only.
        import os

        if path.name not in {
            ".writer-lock",
            ".analysis36-campaign-lock",
        }:
            return None
        path = Path(os.path.abspath(path))
        if path.is_relative_to(root):
            return None
        try:
            original_stat(path, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise PermissionError("existing actual lock cannot be virtualized")
        return lock_targets.setdefault(
            path, locks / sha256(str(path).encode()).hexdigest()
        )

    def mkdir(path, *args, **kwargs):
        return original_mkdir(lock_target(path) or path, *args, **kwargs)

    def rmdir(path, *args, **kwargs):
        return original_rmdir(lock_target(path) or path, *args, **kwargs)

    def stat(path, *args, **kwargs):
        return original_stat(lock_target(path) or path, *args, **kwargs)

    try:
        with (
            patch.object(sqlite3, "connect", connect),
            patch.object(Path, "mkdir", mkdir),
            patch.object(Path, "rmdir", rmdir),
            patch.object(Path, "stat", stat),
        ):
            token = _ISOLATED.set(root)
            namespace_token = _DATABASE_NAMESPACE.set((originals, original_connect))
            try:
                yield {
                    "originals": originals,
                    "redirected": redirected,
                    "lock_targets": lock_targets,
                }
            finally:
                _ISOLATED.reset(token)
                _DATABASE_NAMESPACE.reset(namespace_token)
    finally:
        for source, (_, before) in originals.items():
            assert sha256(source.read_bytes()).hexdigest() == before, (
                "ORIGINAL DATABASE MUTATED: " + str(source)
            )
        assert not any(path.exists() for path in lock_targets), (
            "original historical lock was created"
        )


def reconstruct_historical_databases(data):
    """Build the exact pre-source10 account in NEW private files, SELECT-only outside.

    The complete frozen schema/row multiset is restored, including unknown rows
    and halt state. No current row is deleted or hidden in a copied live account.
    """
    import json
    from copy import deepcopy

    from scripts.task13_pool_prepare import snapshot

    root = _ISOLATED.get()
    if root is None:
        raise PermissionError("historical reconstruction requires private namespace")
    originals, connect = _DATABASE_NAMESPACE.get()
    receipt = (
        data["old_root"].parent
        / "timing-pool-candidate-20261101-2f360b77"
        / "activation/preparation-receipt.json"
    )
    frozen = json.loads(receipt.read_bytes())["database_snapshots"]
    for name, expected in frozen.items():
        original = Path(name).resolve()
        before = sha256(original.read_bytes()).hexdigest()
        if original in originals:
            raise PermissionError("historical database already opened in namespace")
        target = root / ("SYNTHETIC-HISTORICAL-" + original.name)
        if target.exists():
            raise PermissionError("historical reconstruction requires a new database")
        # Snapshot rows omit implicit SQLite rowids, which native budget identity
        # pins. Recover them by exact frozen row bytes from append-only originals.
        rowids = {}
        if "reservations" in expected["tables"]:
            with closing(connect(original.as_uri() + "?mode=ro", uri=True)) as actual:
                rowids = {
                    json.dumps(row[1:]): row[0]
                    for row in actual.execute("SELECT rowid,* FROM reservations")
                }
            assert set(expected["tables"]["reservations"]) <= set(rowids)
        with closing(connect(target)) as db:
            for kind, _, _, sql in expected["schema"]:
                if kind == "table":
                    db.execute(sql)
            for table, rows in expected["tables"].items():
                for encoded in rows:
                    row = json.loads(
                        encoded,
                        object_hook=lambda value: (
                            bytes.fromhex(value["hex"])
                            if set(value) == {"hex"}
                            else value
                        ),
                    )
                    if table == "reservations":
                        db.execute(
                            "INSERT INTO reservations "
                            "(rowid,id,request_key,phase,upper,actual,settled) "
                            "VALUES (?,?,?,?,?,?,?)",
                            (rowids[encoded], *row),
                        )
                    else:
                        db.execute(
                            'INSERT INTO "'
                            + table.replace('"', '""')
                            + '" VALUES ('
                            + ",".join("?" for _ in row)
                            + ")",
                            row,
                        )
            for kind, _, _, sql in expected["schema"]:
                if kind != "table" and sql is not None:
                    db.execute(sql)
            db.commit()
        assert snapshot(target) == expected
        originals[original] = (target, before)
        assert snapshot(original) == expected
    data["database_snapshots"] = deepcopy(frozen)


def register_fixture_metadata(materialization):
    """Run native registration unchanged; caller MUST install isolated_native_io."""
    if not _ISOLATED.get():
        raise PermissionError(
            "fixture registration requires isolated database namespace"
        )
    from evals.adapters.e_planning_journal import register_planning_slots
    from evals.adapters.model_identities import register_model_identity
    from evals.adapters.source_epochs import register_source_epoch
    from evals.contracts import canonical_hash

    m = materialization
    budget = m["source"]["budget_path"]
    for name in m["source"]["controller_state_roots"]:
        path = Path(name)
        if not path.exists():
            if not path.resolve().is_relative_to(_ISOLATED.get()):
                raise PermissionError(
                    "fixture cannot reconstruct historical controller"
                )
            path.mkdir(parents=True)
    for name, function in (
        ("source", register_source_epoch),
        ("model", register_model_identity),
    ):
        value, authority = m[name], m[name + "_authority"]
        function(
            budget,
            value,
            expected_manifest_sha256=canonical_hash(value),
            budget_identity=m["source"]["budget_identity"],
            authority=authority,
            expected_authority_sha256=canonical_hash(authority),
        )
    for child in m["children"]:
        authority = child["authority"]
        path = Path(authority["journal_path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        actual = register_planning_slots(
            path,
            child["planning"],
            expected_registration_sha256=canonical_hash(child["planning"]),
            authority=authority,
            expected_authority_sha256=canonical_hash(authority),
        )
        assert actual == child["dispatch"]


def original_account_baseline(path):
    """Derive exact account baseline from the private SQLite namespace."""
    if not _ISOLATED.get():
        raise PermissionError("fixture baseline requires isolated database namespace")
    from evals.adapters.remediation_worker import _budget_snapshot

    config, original_rows = _budget_snapshot(Path(path))
    with sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True) as db:
        supplement_ids = {
            row[0]
            for row in db.execute("SELECT reservation_id FROM supplement_requests")
        }
    return {
        "config": config,
        "legacy_unknown_rows": [
            list(row)
            for row in original_rows
            if row[0] is not None
            and row[1] not in supplement_ids
            and (row[6] != 1 or row[5] is None)
        ],
    }


@contextmanager
def corrupt_copied_field(path, table, key, row_id, field, replacement):
    """Temporarily corrupt a private DB row; restore row and original triggers."""
    if not _ISOLATED.get():
        raise PermissionError("SQL negative fixture requires private namespace")
    allowed = {
        ("supplement_source_epochs", "epoch_id", "manifest_json"),
        ("supplement_model_epochs", "model_epoch_id", "manifest_json"),
        ("supplement_request_models", "reservation_id", "identity_manifest_sha256"),
        ("reservations", "id", "settled"),
    }
    if (table, key, field) not in allowed:
        raise ValueError("fixture corruption target is not allowlisted")
    with closing(sqlite3.connect(path)) as db:
        triggers = db.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?",
            (table,),
        ).fetchall()
        original = db.execute(
            f'SELECT "{field}" FROM "{table}" WHERE "{key}"=?', (row_id,)
        ).fetchone()
        assert original is not None
        for name, _ in triggers:
            db.execute('DROP TRIGGER "' + name.replace('"', '""') + '"')
        db.execute(
            f'UPDATE "{table}" SET "{field}"=? WHERE "{key}"=?', (replacement, row_id)
        )
        db.commit()
        try:
            yield
        finally:
            db.execute(
                f'UPDATE "{table}" SET "{field}"=? WHERE "{key}"=?',
                (original[0], row_id),
            )
            for _, sql in triggers:
                db.execute(sql)
            db.commit()


def mirrored_fixture_compiler(root):
    """Run the legacy v1 producer from its full compatible frozen source tree.

    Every production file comes from 2f360b77, whose complete 117 worker map is
    identical to C10. Only test harness files are current; all are host-frozen.
    This proves historical v1 behavior, never current changed-worker equivalence.
    """
    import io
    import subprocess
    import zipfile
    from types import FunctionType

    from evals.tests import pool_composite_prepare_fixture as fixture

    tree = Path(__file__).resolve().parents[2]
    mirror = Path(root).resolve() / "FROZEN-SYNTHETIC-HOST-SOURCE"
    data = fixture.original_templates()
    commit = "2f360b77b72d0ac49609aa06b1aca3e8a16fe705"
    archive = subprocess.check_output(
        [
            "git",
            "archive",
            "--format=zip",
            commit,
            "services/backend/src",
            "services/backend/tests",
            "services/backend/pyproject.toml",
            "services/backend/uv.lock",
            "evals",
            "scripts",
            "docs/evaluations/protocol.md",
        ],
        cwd=tree,
    )
    mirror.mkdir(parents=True)
    with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
        bundle.extractall(mirror)
    for name in (
        "pool_composite_fixture.py",
        "pool_composite_prepare_fixture.py",
        "pool_composite_planning_fixture.py",
        "test_pool_composite_integration.py",
        "test_pool_composite_planning_fixture.py",
    ):
        relative = "evals/tests/" + name
        (mirror / relative).write_bytes((tree / relative).read_bytes())
    assert len(data["receipt"]["files"]) == 117
    for name, digest in data["receipt"]["files"].items():
        assert sha256((mirror / name).read_bytes()).hexdigest() == digest
    original = fixture.compile_fixture_documents
    namespace = {
        **original.__globals__,
        "__file__": str(mirror / "evals/tests/pool_composite_prepare_fixture.py"),
    }
    clone = FunctionType(
        original.__code__, namespace, original.__name__, original.__defaults__
    )
    clone.__kwdefaults__ = original.__kwdefaults__
    return clone, mirror


async def enter_mirrored_test(
    tmp_path, test_name, *, test_file="test_pool_composite_integration.py"
):
    """Return mirror inside child, or run the complete test in an isolated child."""
    import asyncio
    import os
    import subprocess
    import sys

    marker = "TASK13_SYNTHETIC_TEST_SOURCE_MIRROR"
    if marker in os.environ:
        mirror = Path(os.environ[marker])
        assert Path(__file__).resolve().parents[2] == mirror
        return mirror
    _, mirror = mirrored_fixture_compiler(tmp_path)
    code = (
        "import sys;sys.path[:0]="
        + repr([str(mirror), str(mirror / "services/backend/src")])
        + ";import pytest;raise SystemExit(pytest.main("
        + repr(
            [
                str(mirror / "evals/tests" / test_file),
                "-vv",
                "-k",
                test_name,
                "--basetemp=" + str(tmp_path / "mirror-run"),
            ]
        )
        + "))"
    )
    result = await asyncio.to_thread(
        subprocess.run,
        [sys.executable, "-I", "-B", "-X", "utf8", "-c", code],
        cwd=mirror,
        env={**os.environ, marker: str(mirror)},
        capture_output=True,
        encoding="utf8",
        timeout=1800,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return None
