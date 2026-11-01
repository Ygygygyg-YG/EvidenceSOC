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
    original_mkdir, original_rmdir = Path.mkdir, Path.rmdir
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
        path = path.resolve()
        if path.is_relative_to(root) or path.name not in {
            ".writer-lock",
            ".analysis36-campaign-lock",
        }:
            return None
        if path.exists():
            raise PermissionError("existing actual lock cannot be virtualized")
        return lock_targets.setdefault(
            path, locks / sha256(str(path).encode()).hexdigest()
        )

    def mkdir(path, *args, **kwargs):
        return original_mkdir(lock_target(path) or path, *args, **kwargs)

    def rmdir(path, *args, **kwargs):
        return original_rmdir(lock_target(path) or path, *args, **kwargs)

    try:
        with (
            patch.object(sqlite3, "connect", connect),
            patch.object(Path, "mkdir", mkdir),
            patch.object(Path, "rmdir", rmdir),
        ):
            token = _ISOLATED.set(root)
            try:
                yield {
                    "originals": originals,
                    "redirected": redirected,
                    "lock_targets": lock_targets,
                }
            finally:
                _ISOLATED.reset(token)
    finally:
        for source, (_, before) in originals.items():
            assert sha256(source.read_bytes()).hexdigest() == before, (
                "ORIGINAL DATABASE MUTATED: " + str(source)
            )
        assert not any(path.exists() for path in lock_targets), (
            "original historical lock was created"
        )


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
    """Freeze every evaluated host file into a private byte-identical test tree.

    The pure test compiler derives its tree from __file__. Its private function
    namespace points at that same copied helper, leaving its module unchanged.
    No production verifier or source path is substituted.
    """
    import shutil
    from types import FunctionType

    from evals.freeze import required_freeze_files
    from evals.tests import pool_composite_prepare_fixture as fixture

    tree = Path(__file__).resolve().parents[2]
    mirror = Path(root).resolve() / "FROZEN-SYNTHETIC-HOST-SOURCE"
    data = fixture.original_templates()
    names = (
        set(required_freeze_files(tree))
        | set(data["receipt"]["files"])
        | set(data["source"]["entrypoints"])
    )
    for name in names:
        target = mirror / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(tree / name, target)
        assert target.read_bytes() == (tree / name).read_bytes()
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


async def enter_mirrored_test(tmp_path, test_name):
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
                str(mirror / "evals/tests/test_pool_composite_integration.py"),
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
