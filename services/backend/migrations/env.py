import os
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from evidencesoc.api.tables import ApiBase
from evidencesoc.persistence.tables import Base
from sqlalchemy import engine_from_config, pool

config = context.config


def read_database_url() -> str:
    environment_value = os.getenv("DATABASE_URL")
    if environment_value:
        return environment_value

    repository_root = Path(__file__).resolve().parents[3]

    for filename in (".env", ".env.example"):
        path = repository_root / filename
        if not path.exists():
            continue

        for line in path.read_text(encoding="utf-8").splitlines():
            value = line.strip()

            if (
                not value
                or value.startswith("#")
                or "=" not in value
            ):
                continue

            key, raw_value = value.split("=", 1)

            if key.strip() == "DATABASE_URL":
                return raw_value.strip().strip("\"'")

    raise RuntimeError("Missing required setting: DATABASE_URL")


if config.config_file_name is not None:
    fileConfig(config.config_file_name)

database_url = read_database_url()
config.set_main_option(
    "sqlalchemy.url",
    database_url.replace("%", "%%"),
)

target_metadata = [Base.metadata, ApiBase.metadata]

UNMANAGED_TABLE_NAMES = {
    "task3_persistence_probe",
    "checkpoint_migrations",
    "checkpoints",
    "checkpoint_blobs",
    "checkpoint_writes",
}


def include_object(
    _object: object,
    name: str | None,
    type_: str,
    _reflected: bool,
    _compare_to: object | None,
) -> bool:
    return not (
        type_ == "table"
        and name in UNMANAGED_TABLE_NAMES
    )


def run_migrations_offline() -> None:
    """Run migrations without opening a database connection."""
    url = config.get_main_option("sqlalchemy.url")

    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        include_object=include_object,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations using a database connection."""
    connectable = engine_from_config(
        config.get_section(
            config.config_ini_section,
            {},
        ),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            include_object=include_object,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
