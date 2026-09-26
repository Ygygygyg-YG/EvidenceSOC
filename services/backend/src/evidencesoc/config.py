from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = BACKEND_ROOT.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=REPOSITORY_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = (
        "postgresql+psycopg://"
        "evidencesoc:change-me-local-only@127.0.0.1:5432/evidencesoc"
    )
    opensearch_url: str = "http://127.0.0.1:9200"
    opensearch_index: str = "security-events-v1"

    llm_mode: Literal["fixture", "deepseek"] = "fixture"
    deepseek_api_key: SecretStr | None = None
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-flash"


@lru_cache
def get_settings() -> Settings:
    return Settings()
