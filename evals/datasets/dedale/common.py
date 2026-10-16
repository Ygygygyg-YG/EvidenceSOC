"""Small, path-independent serialization and fixed-source integrity helpers."""
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath

OFFICIAL = {
    "system_logs_auditbeat.zip": (717881, 10_896_385_060, "d01b50094a93aa5ebc8a46e6150d256b"),
    "system_logs_winlogbeat.zip": (717892, 27_123_250_952, "7af54ba2977f7535d4c07beb6b1ec657"),
    "system_logs_labels.zip": (717882, 2_669_407, "455d0a7042531eff74285006f97822e4"),
}


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256(path: Path) -> str:
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path: Path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject(value):
        raise ValueError("nonfinite JSON constant")

    return json.loads(Path(path).read_text(encoding="utf-8-sig"), object_pairs_hook=unique, parse_constant=reject)


def safe_file(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("file reference must be relative POSIX")
    path = PurePosixPath(relative)
    if path.is_absolute() or PureWindowsPath(relative).drive or any(x in {"", ".", ".."} for x in relative.split("/")) or ":" in relative:
        raise ValueError("unsafe file reference")
    root = Path(root).absolute()
    result = root.joinpath(*path.parts)
    for part in [*reversed(result.parents), result]:
        if part.is_symlink() or part.is_junction():
            raise ValueError("file reference must not traverse a filesystem link")
    if not result.resolve().is_relative_to(root.resolve()):
        raise ValueError("file reference escapes data root")
    return result


def write_new(path: Path, value, *, jsonl=False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = "".join(canonical(row) + "\n" for row in value) if jsonl else canonical(value) + "\n"
    with path.open("xb") as stream:
        stream.write(data.encode("utf-8"))


def verify_sources(sources: Path, data_root: Path, *, check_crc: bool = True) -> dict:
    """Require all three fixed-version archives, official MD5, SHA256 and CRC.

    Archive SHA256 is calculated locally, rather than being an unverified value
    copied into the source manifest. No partial download is a verified source.
    """
    config = read_json(sources)
    if config.get("version") != "2.1" or config.get("doi") != "10.57745/Y5JLDG" or config.get("license") != "CC-BY-4.0":
        raise ValueError("unsupported source version or license")
    rows = config.get("archives", [])
    if len(rows) != len(OFFICIAL) or {r["path"] for r in rows} != set(OFFICIAL):
        raise ValueError("all three required official archives are mandatory")
    # Reject incomplete acquisitions before reading tens of GB from another ZIP.
    for row in rows:
        path = safe_file(data_root, row["path"])
        if path.stat().st_size != OFFICIAL[row["path"]][1]:
            raise ValueError("incomplete archive")
    snapshot = config["metadata_snapshot"]
    snapshot_path = safe_file(data_root, snapshot["path"])
    if sha256(snapshot_path) != snapshot["sha256"]:
        raise ValueError("official metadata snapshot changed")
    metadata = read_json(snapshot_path)["data"]
    if (metadata["versionNumber"], metadata["versionMinorNumber"]) != (2, 1):
        raise ValueError("metadata does not identify V2.1")
    metadata_files = {r["dataFile"]["filename"]: r["dataFile"] for r in metadata["files"]}
    verified = []
    for row in sorted(rows, key=lambda value: value["path"]):
        expected_id, expected_size, expected_md5 = OFFICIAL[row["path"]]
        expected_url = f"https://entrepot.recherche.data.gouv.fr/api/access/datafile/{expected_id}"
        if (row["datafile_id"], row["bytes"], row["md5"], row["url"]) != (expected_id, expected_size, expected_md5, expected_url):
            raise ValueError("source metadata differs from pinned official values")
        official = metadata_files[row["path"]]
        if (official["id"], official["filesize"], official["checksum"]["value"]) != (expected_id, expected_size, expected_md5):
            raise ValueError("archive differs from version snapshot")
        path = safe_file(data_root, row["path"])
        if path.stat().st_size != expected_size:
            raise ValueError("incomplete archive")
        md5, strong = hashlib.md5(), hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
                md5.update(block)
                strong.update(block)
        if md5.hexdigest() != expected_md5:
            raise ValueError("official archive MD5 mismatch")
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)):
                raise ValueError("duplicate ZIP member")
            if check_crc and archive.testzip() is not None:
                raise ValueError("archive CRC check failed")
            member_count = sum(not r.is_dir() for r in archive.infolist())
        verified.append({"path": row["path"], "bytes": expected_size, "md5": expected_md5,
                         "sha256": strong.hexdigest(), "crc_checked": check_crc, "members": member_count})
    return {"verified": True, "archives": verified, "sources_sha256": sha256(sources),
            "metadata_sha256": snapshot["sha256"]}


def is_hash(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
