from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import SecretStr, field_validator, model_validator
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
    rag_data_directory: Path = REPOSITORY_ROOT / "data" / "knowledge"

    @field_validator("rag_data_directory")
    @classmethod
    def absolute_knowledge_directory(cls, value: Path) -> Path:
        return value if value.is_absolute() else REPOSITORY_ROOT / value

    llm_mode: Literal["fixture", "deepseek"] = "fixture"
    deepseek_api_key: SecretStr | None = None
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-flash"
    demo_session_enabled: bool = False
    demo_sqli_enabled: bool = False
    demo_sqli_directory: Path = REPOSITORY_ROOT / ".tmp" / "sqli-demo"
    frontend_origin: str = "http://127.0.0.1:3000"

    @field_validator("demo_sqli_directory")
    @classmethod
    def absolute_demo_directory(cls, value: Path) -> Path:
        return value if value.is_absolute() else REPOSITORY_ROOT / value

    @model_validator(mode="after")
    def require_local_demo_session(self):
        if self.demo_sqli_enabled and not self.demo_session_enabled:
            raise ValueError("SQL injection demo requires the local demo session")
        return self

    @field_validator("frontend_origin")
    @classmethod
    def local_frontend_origin(cls, value: str) -> str:
        origin = urlsplit(value)
        try:
            port = origin.port
        except ValueError:
            port = None
        if (
            origin.scheme not in {"http", "https"}
            or origin.hostname not in {"127.0.0.1", "localhost", "::1"}
            or port is None
            or origin.username is not None
            or origin.password is not None
            or origin.path
            or origin.query
            or origin.fragment
            or value != f"{origin.scheme}://{origin.netloc}"
        ):
            raise ValueError(
                "frontend_origin must be a loopback HTTP(S) origin with a port"
            )
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
