from __future__ import annotations

from pathlib import Path

import pytest

from evidencesoc.config import BACKEND_ROOT, REPOSITORY_ROOT, Settings


def test_default_dotenv_path_is_absolute_repository_root() -> None:
    env_file = Path(Settings.model_config["env_file"])
    assert env_file.is_absolute()
    assert env_file == REPOSITORY_ROOT / ".env"
    assert BACKEND_ROOT == REPOSITORY_ROOT / "services" / "backend"


def test_settings_result_does_not_depend_on_working_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENSEARCH_URL", raising=False)
    monkeypatch.chdir(REPOSITORY_ROOT)
    root_value = Settings().opensearch_url
    monkeypatch.chdir(BACKEND_ROOT)
    backend_value = Settings().opensearch_url

    assert backend_value == root_value


def test_environment_value_overrides_explicit_dotenv() -> None:
    value = "http://127.0.0.1:19202"

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setenv("OPENSEARCH_URL", value)
        assert (
            Settings(_env_file=REPOSITORY_ROOT / ".env.example").opensearch_url
            == value
        )


def test_env_file_none_ignores_dotenv() -> None:
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.delenv("OPENSEARCH_URL", raising=False)
        settings = Settings(_env_file=None)

    assert settings.opensearch_url == "http://127.0.0.1:9200"
