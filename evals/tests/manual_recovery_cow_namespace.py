"""Test-only logical path namespace; supplementary evidence, never adoption proof.

Every sqlite3.Connection is native. Only the exact allowlisted PRAGMA
database_list result has its main physical filename translated to its logical
source identity. This proxy is disclosed in the result; it does not demonstrate
the production original-filename guard. No production validator is patched.
"""

from __future__ import annotations

import os
import shutil
import sqlite3
import stat
import sys
from contextlib import ExitStack, closing
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
from urllib.parse import unquote, urlsplit


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def sql_snapshot(path, *, connection_factory=None):
    import json

    connect = connection_factory or sqlite3.connect
    with closing(connect(Path(path).as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        schema = db.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()
        tables, rowids = {}, {}
        for kind, name, _, definition in schema:
            if kind != "table":
                continue
            quoted = '"' + name.replace('"', '""') + '"'
            encode = lambda row: json.dumps(
                row, default=lambda value: {"hex": value.hex()}
            )
            tables[name] = sorted(map(encode, db.execute("SELECT * FROM " + quoted)))
            if "WITHOUT ROWID" not in (definition or "").upper():
                rowids[name] = sorted(
                    map(encode, db.execute("SELECT rowid,* FROM " + quoted))
                )
        return {
            "schema": [list(row) for row in schema],
            "tables": tables,
            "rowids": rowids,
        }


class MappedCursor:
    """Map only DB identity rows, preserving native cursor execution underneath."""

    def __init__(self, cursor, mapping, record):
        self.cursor, self.mapping, self.record = cursor, mapping, record

    def _row(self, row):
        if row is None:
            return None
        values = list(row)
        if len(values) == 3 and values[1] == "main" and values[2]:
            physical = str(Path(values[2]).absolute())
            if physical not in self.mapping:
                raise PermissionError("PRAGMA physical DB identity is not allowlisted")
            logical = self.mapping[physical]
            self.record.append({"physical": physical, "logical": logical})
            values[2] = logical
        return tuple(values)

    def fetchone(self):
        return self._row(self.cursor.fetchone())

    def fetchall(self):
        return [self._row(row) for row in self.cursor.fetchall()]

    def fetchmany(self, *args):
        return [self._row(row) for row in self.cursor.fetchmany(*args)]

    def __iter__(self):
        return (self._row(row) for row in self.cursor)

    def __getattr__(self, name):
        return getattr(self.cursor, name)


class CowNamespace:
    """Mirror authentic filesystem inodes and DB state below one private root.

    Path strings, pins, FROZEN anchors, native leases/capabilities and validators
    are unchanged. All source roots are copied before patching. All writes go to
    the private root; external reads are allowed. A CPython audit hook additionally
    refuses unhandled Python filesystem write paths. It is not an OS sandbox.
    """

    def __init__(self, root, logical_roots):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=False)
        self.raw = {
            name: getattr(Path, name)
            for name in (
                "open",
                "stat",
                "lstat",
                "resolve",
                "mkdir",
                "rmdir",
                "unlink",
                "iterdir",
                "glob",
                "rglob",
                "rename",
                "replace",
                "touch",
            )
        }
        self.connect_raw = sqlite3.connect
        self.raw_os = {name: getattr(os, name) for name in ("link", "replace")}
        self.lstat_unpatched = os.lstat
        self.realpath_unpatched = os.path.realpath
        self.canonical_root = Path(self.realpath_unpatched(self.root, strict=True))
        self.preservation_verification_completed = False
        self.original_preservation_verified = False
        self.os_publications = []
        self.maps, self.databases, self.identities, self.pragma_events = {}, {}, {}, []
        self.writes, self.refused, self.before_files = [], [], {}
        self.active = False
        roots = sorted(
            {Path(value).absolute() for value in logical_roots},
            key=lambda p: len(p.parts),
        )
        for logical in roots:
            if logical.is_relative_to(self.root) or any(
                logical.is_relative_to(p) for p in self.maps
            ):
                continue
            if logical.is_symlink() or logical.is_junction():
                raise PermissionError("original root is linked")
            physical = self.root / "trees" / sha256(str(logical).encode()).hexdigest()
            physical.parent.mkdir(exist_ok=True)
            if logical.exists():
                for path in logical.rglob("*"):
                    if path.is_symlink() or path.is_junction():
                        raise PermissionError("original descendant is linked")
                    if path.name in {
                        "host-writer.lock",
                        "pool-journal.jsonl.lock",
                        ".pool-adoption-fence",
                        ".writer-lock",
                        ".analysis36-campaign-lock",
                        ".rolling-adoption-lock",
                    }:
                        raise PermissionError(
                            "original active/stale lock cannot be hidden"
                        )
                    if path.is_file():
                        self.before_files[str(path)] = digest(path)
                shutil.copytree(logical, physical)
            else:
                physical.mkdir()
            self.maps[logical] = physical

    def physical(self, value):
        path = Path(value).absolute()
        for logical in sorted(self.maps, key=lambda p: len(p.parts), reverse=True):
            if path.is_relative_to(logical):
                return self.maps[logical] / path.relative_to(logical)
        return path

    def logical(self, value):
        path = Path(value).absolute()
        for logical, physical in self.maps.items():
            if path.is_relative_to(physical):
                return logical / path.relative_to(physical)
        return path

    def _write(self, physical):
        path = Path(physical)
        safe = path.is_absolute() and ".." not in path.parts
        if safe:
            try:
                canonical = Path(self.realpath_unpatched(path, strict=False))
                safe = canonical.is_relative_to(self.canonical_root)
                for parent in (path, *path.parents):
                    try:
                        metadata = self.lstat_unpatched(parent)
                    except FileNotFoundError:
                        continue
                    if (
                        stat.S_ISLNK(metadata.st_mode)
                        or getattr(metadata, "st_file_attributes", 0) & 0x400
                    ):
                        safe = False
                        break
            except OSError:
                safe = False
        if not safe:
            self.refused.append(str(path))
            raise PermissionError("COW harness refused external filesystem write")
        self.writes.append(str(path))
        return path

    def _uri_path(self, database, uri):
        if uri and str(database).startswith("file:"):
            parsed = urlsplit(str(database))
            name = unquote(parsed.path)
            if len(name) > 2 and name[0] == "/" and name[2] == ":":
                name = name[1:]
            return Path(name).absolute(), parsed.query
        return Path(database).absolute(), ""

    def _copy_database(self, logical):
        physical = self.physical(logical)
        if physical == logical:
            physical = (
                self.root
                / "sqlite"
                / (sha256(str(logical).encode()).hexdigest() + ".sqlite")
            )
        physical.parent.mkdir(parents=True, exist_ok=True)
        before = self.raw["stat"](logical)
        with self.raw["open"](logical, "rb") as stream:
            raw = stream.read()
        if not logical.is_file():
            raise PermissionError("external database must already exist")
        sidecars = {}
        for suffix in ("-wal", "-shm"):
            path = Path(str(logical) + suffix)
            try:
                with self.raw["open"](path, "rb") as stream:
                    sidecars[str(path)] = sha256(stream.read()).hexdigest()
            except FileNotFoundError:
                sidecars[str(path)] = None
        baseline = sql_snapshot(logical, connection_factory=self.connect_raw)
        # SQLite native backup reads the actual original under mode=ro and includes WAL.
        with (
            closing(
                self.connect_raw(logical.as_uri() + "?mode=ro", uri=True)
            ) as source,
            closing(self.connect_raw(physical)) as destination,
        ):
            source.backup(destination)
        assert sql_snapshot(physical, connection_factory=self.connect_raw) == baseline
        import json

        baseline_file = (
            self.root
            / "sqlite-baselines"
            / (sha256(str(logical).encode()).hexdigest() + ".json")
        )
        baseline_file.parent.mkdir(exist_ok=True)
        baseline_file.write_text(json.dumps(baseline, sort_keys=True), encoding="utf-8")
        self.databases[str(logical)] = {
            "physical": str(physical),
            "before_sha256": sha256(raw).hexdigest(),
            "before_size": before.st_size,
            "sidecars_before": sidecars,
            "all_schema_rows_rowids_equal_at_copy": True,
            "full_sql_baseline": {
                "path": str(baseline_file),
                "sha256": digest(baseline_file),
            },
        }
        self.identities[str(physical.absolute())] = str(logical)
        return physical

    def _audit(self, event, args):
        if not self.active:
            return
        if event == "open":
            path, mode, flags = args
            if isinstance(path, (str, bytes, os.PathLike)) and (
                (isinstance(mode, str) and any(value in mode for value in "wax+"))
                or (
                    isinstance(flags, int)
                    and flags
                    & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
                )
            ):
                self._write(path)
        elif event in {"os.mkdir", "os.rmdir", "os.remove", "os.chmod", "os.utime"}:
            self._write(args[0])
        elif event in {"os.rename", "os.link", "os.symlink"}:
            for path in args[:2]:
                self._write(path)

    def __enter__(self):
        self.preservation_verification_completed = False
        self.original_preservation_verified = False
        namespace = self

        class NativeMappedConnection(sqlite3.Connection):
            def execute(self, sql, parameters=()):
                cursor = super().execute(sql, parameters)
                if sql.strip().rstrip(";").strip().lower() == "pragma database_list":
                    return MappedCursor(
                        cursor, namespace.identities, namespace.pragma_events
                    )
                return cursor

        def connect(database, *args, **kwargs):
            if str(database) == ":memory:":
                return self.connect_raw(database, *args, **kwargs)
            logical, query = self._uri_path(database, kwargs.get("uri", False))
            physical = self.physical(logical)
            if not logical.is_relative_to(self.root):
                if str(logical) not in self.databases:
                    try:
                        self.raw["stat"](logical)
                    except FileNotFoundError:
                        if physical == logical:
                            raise PermissionError(
                                "external new DB has no private mapping"
                            ) from None
                        self._write(physical)
                        self.identities[str(physical.absolute())] = str(logical)
                    else:
                        physical = self._copy_database(logical)
                if str(logical) in self.databases:
                    physical = Path(self.databases[str(logical)]["physical"])
            if "factory" in kwargs:
                raise PermissionError(
                    "custom SQLite factory outside transport contract"
                )
            kwargs["factory"] = NativeMappedConnection
            target = (
                physical.as_uri() + ("?" + query if query else "")
                if kwargs.get("uri", False)
                else physical
            )
            return self.connect_raw(target, *args, **kwargs)

        def opened(path, mode="r", *args, **kwargs):
            physical = self.physical(path)
            if any(value in mode for value in "wax+"):
                self._write(physical)
            return self.raw["open"](physical, mode, *args, **kwargs)

        def resolved(path, *args, **kwargs):
            # Logical mapped paths resolve canonically through the private tree;
            # an already physical SQLite filename remains physical. The declared
            # PRAGMA mapping above is the only DB filename identity translation.
            physical = self.physical(path)
            resolved_path = self.raw["resolve"](physical, *args, **kwargs)
            return (
                self.logical(resolved_path)
                if physical != Path(path).absolute()
                else resolved_path
            )

        def unary_write(name):
            def operation(path, *args, **kwargs):
                return self.raw[name](self._write(self.physical(path)), *args, **kwargs)

            return operation

        def moved(name):
            def operation(path, target):
                self.raw[name](
                    self._write(self.physical(path)), self._write(self.physical(target))
                )
                return Path(target)

            return operation

        def scan(name):
            def operation(path, *args, **kwargs):
                physical = self.physical(path)
                for value in self.raw[name](physical, *args, **kwargs):
                    yield (
                        self.logical(value)
                        if physical != Path(path).absolute()
                        else value
                    )

            return operation

        def os_publish(name):
            def operation(source, target, *args, **kwargs):
                if any(
                    kwargs.get(key) is not None for key in ("src_dir_fd", "dst_dir_fd")
                ):
                    raise PermissionError("COW OS publication requires absolute paths")
                source_physical = self._write(self.physical(source))
                target_physical = self._write(self.physical(target))
                self.os_publications.append(
                    {
                        "operation": "os." + name,
                        "logical_source": str(source),
                        "logical_target": str(target),
                        "physical_source": str(source_physical),
                        "physical_target": str(target_physical),
                    }
                )
                return self.raw_os[name](
                    source_physical, target_physical, *args, **kwargs
                )

            return operation

        self.stack = ExitStack()
        self.stack.enter_context(patch.object(sqlite3, "connect", connect))
        self.stack.enter_context(patch.object(Path, "open", opened))
        self.stack.enter_context(patch.object(Path, "resolve", resolved))
        for name in ("stat", "lstat"):
            self.stack.enter_context(
                patch.object(
                    Path,
                    name,
                    lambda path, *a, _n=name, **k: self.raw[_n](
                        self.physical(path), *a, **k
                    ),
                )
            )
        for name in ("mkdir", "rmdir", "unlink", "touch"):
            self.stack.enter_context(patch.object(Path, name, unary_write(name)))
        for name in ("rename", "replace"):
            self.stack.enter_context(patch.object(Path, name, moved(name)))
        for name in ("iterdir", "glob", "rglob"):
            self.stack.enter_context(patch.object(Path, name, scan(name)))
        for name in ("link", "replace"):
            self.stack.enter_context(patch.object(os, name, os_publish(name)))
        sys.addaudithook(self._audit)
        self.active = True
        return self

    def __exit__(self, kind, error, traceback):
        self.active = False
        self.stack.close()
        after_files = {}
        for root in self.maps:
            if root.exists():
                for path in root.rglob("*"):
                    if path.name in {
                        "host-writer.lock",
                        "pool-journal.jsonl.lock",
                        ".pool-adoption-fence",
                        ".writer-lock",
                        ".analysis36-campaign-lock",
                        ".rolling-adoption-lock",
                    }:
                        raise AssertionError("ORIGINAL LOCK CREATED: " + str(path))
                    if path.is_file():
                        after_files[str(path)] = digest(path)
        if after_files != self.before_files:
            raise AssertionError("ORIGINAL COMPLETE FILE INVENTORY CHANGED")
        for logical, expected in self.before_files.items():
            if digest(logical) != expected:
                raise AssertionError("ORIGINAL RAW FILE CHANGED: " + logical)
        for logical, entry in self.databases.items():
            entry["after_sha256"] = digest(logical)
            if entry["after_sha256"] != entry["before_sha256"]:
                raise AssertionError("ORIGINAL SQLITE CHANGED: " + logical)
            for path, expected in entry["sidecars_before"].items():
                actual = digest(path) if Path(path).exists() else None
                if actual != expected:
                    raise AssertionError("ORIGINAL SQLITE SIDECAR CHANGED: " + path)
        self.preservation_verification_completed = True
        self.original_preservation_verified = True

    def report(self):
        return {
            "evidence_kind": "namespace-virtualized-native-integration-supplementary",
            "production_adoption_proof": False,
            "sqlite_connection": "native sqlite3.Connection subclass",
            "pragma_database_list_proxy": True,
            "pragma_identity_mapping": dict(self.identities),
            "pragma_translation_events": list(self.pragma_events),
            "native_os_publication_transports": list(self.os_publications),
            "file_root_mapping": {
                str(key): str(value) for key, value in self.maps.items()
            },
            "database_copies": dict(self.databases),
            "original_raw_files_checked": len(self.before_files),
            "original_complete_file_inventory_compared": self.original_preservation_verified,
            "preservation_verification_completed": self.preservation_verification_completed,
            "original_preservation_verified": self.original_preservation_verified,
            "refused_external_writes": list(self.refused),
            "production_validator_patches": [],
            "real_original_path_audit_required_separately": True,
        }
