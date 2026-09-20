import os
from pathlib import Path

import httpx
import psycopg


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


def read_setting(name: str) -> str:
    environment_value = os.getenv(name)
    if environment_value:
        return environment_value

    for filename in (".env", ".env.example"):
        path = REPOSITORY_ROOT / filename
        if not path.exists():
            continue

        for line in path.read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if not value or value.startswith("#") or "=" not in value:
                continue

            key, raw_value = value.split("=", 1)
            if key.strip() == name:
                return raw_value.strip().strip("\"'")

    raise RuntimeError(f"Missing required setting: {name}")


def postgres_dsn() -> str:
    return read_setting("DATABASE_URL").replace(
        "postgresql+psycopg://",
        "postgresql://",
        1,
    )


def opensearch_url() -> str:
    return read_setting("OPENSEARCH_URL").rstrip("/")


def test_postgres_and_pgvector_versions() -> None:
    with psycopg.connect(postgres_dsn(), connect_timeout=5) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            assert cursor.fetchone() == (1,)

            cursor.execute("SHOW server_version")
            server_version = cursor.fetchone()
            assert server_version is not None
            assert server_version[0].startswith("17.")

            cursor.execute(
                "SELECT extversion "
                "FROM pg_extension "
                "WHERE extname = 'vector'"
            )
            assert cursor.fetchone() == ("0.8.6",)


def test_opensearch_version_and_health() -> None:
    root_response = httpx.get(opensearch_url(), timeout=10)
    root_response.raise_for_status()
    assert root_response.json()["version"]["number"] == "3.8.0"

    health_response = httpx.get(
        f"{opensearch_url()}/_cluster/health",
        timeout=10,
    )
    health_response.raise_for_status()
    assert health_response.json()["status"] in {"yellow", "green"}


def test_security_events_template_is_installed() -> None:
    response = httpx.get(
        f"{opensearch_url()}/_index_template/security-events",
        timeout=10,
    )
    response.raise_for_status()

    template_names = {
        item["name"] for item in response.json()["index_templates"]
    }
    assert "security-events" in template_names