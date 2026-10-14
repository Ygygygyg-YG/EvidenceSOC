from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import httpx
import pytest
from evidencesoc.rag import cli


def test_pinned_download_records_exact_bytes_hash_version_and_download_date(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b'{"type":"bundle","objects":[]}'
    monkeypatch.setattr(cli, "PINNED_STIX_SHA256", hashlib.sha256(payload).hexdigest())
    calls = []

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, content=payload)

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        path, manifest = cli.prepare_attack_source(tmp_path, client=client)
        assert path.read_bytes() == payload
        assert manifest.version == "19.2"
        assert manifest.downloaded_at.utcoffset() is not None
        assert (
            json.loads((tmp_path / "enterprise-attack-19.2.manifest.json").read_text())[
                "sha256"
            ]
            == manifest.sha256
        )
        path2, manifest2 = cli.prepare_attack_source(tmp_path, client=client)
        assert path2 == path and manifest2 == manifest
    assert calls == [cli.PINNED_STIX_URL]


def test_invalid_download_is_rejected_without_publishing_a_source(
    tmp_path: Path,
) -> None:
    with (
        httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, content=b"wrong")
            )
        ) as client,
        pytest.raises(ValueError, match="hash"),
    ):
        cli.prepare_attack_source(tmp_path, client=client)
    assert not (tmp_path / "enterprise-attack-19.2.json").exists()


def test_existing_source_with_modified_bytes_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "enterprise-attack-19.2.json").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="hash"):
        cli.prepare_attack_source(tmp_path)


def test_cli_rejects_a_directory_that_runtime_is_not_configured_to_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[Path | None] = []
    monkeypatch.setattr(
        sys,
        "argv",
        ["knowledge", "prepare", "--data-directory", str(tmp_path / "other")],
    )
    monkeypatch.setattr(
        cli, "prepare_knowledge", lambda directory: calls.append(directory)
    )
    with pytest.raises(SystemExit) as error:
        cli.main()
    assert error.value.code == 2
    assert calls == []


def test_cli_custom_directory_matches_the_runtime_setting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[Path | None] = []
    monkeypatch.setenv("RAG_DATA_DIRECTORY", str(tmp_path))
    monkeypatch.setattr(
        sys, "argv", ["knowledge", "prepare", "--data-directory", str(tmp_path)]
    )
    monkeypatch.setattr(
        cli, "prepare_knowledge", lambda directory: calls.append(directory)
    )
    cli.main()
    assert calls == [tmp_path]
