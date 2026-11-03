"""Fail-closed ownership checks for explicitly opted-in Task14 containers."""

import json
import os
import re
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from urllib.parse import urlsplit

import pytest
from evidencesoc.config import Settings


def docker(*args):
    result = subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=35,
        check=False,
    )
    # Do not expose docker inspect/config output (container env may hold credentials).
    if result.returncode:
        raise RuntimeError(f"owned Docker operation failed: {args[0]}")
    return result.stdout


@dataclass(frozen=True)
class OwnedServices:
    project: str
    settings: Settings

    def container(self, service):
        assert service in {"postgres", "opensearch"}
        ids = docker(
            "ps",
            "-aq",
            "--filter",
            f"label=com.docker.compose.project={self.project}",
            "--filter",
            f"label=com.docker.compose.service={service}",
        ).split()
        assert len(ids) == 1, "exactly one owned dependency container required"
        value = json.loads(docker("inspect", ids[0]))[0]
        labels = value["Config"]["Labels"]
        assert labels["com.docker.compose.project"] == self.project
        assert labels["com.docker.compose.service"] == service
        assert value["Name"].lstrip("/") not in {
            "evidencesoc-postgres-1",
            "evidencesoc-opensearch-1",
        }
        url = urlsplit(
            self.settings.database_url
            if service == "postgres"
            else self.settings.opensearch_url
        )
        assert url.hostname in {"127.0.0.1", "localhost"}
        assert url.port is not None and url.port not in {5432, 9200, 9201}
        internal = "5432/tcp" if service == "postgres" else "9200/tcp"
        mappings = value["HostConfig"]["PortBindings"][internal]
        assert mappings == [{"HostIp": "127.0.0.1", "HostPort": str(url.port)}]
        return value["Id"]

    @contextmanager
    def stopped(self, service):
        identity = self.container(service)
        assert json.loads(docker("inspect", identity))[0]["State"]["Running"]
        try:
            docker("stop", "--time", "2", identity)
            assert not json.loads(docker("inspect", identity))[0]["State"]["Running"]
            print(
                f"task14_fault project={self.project} service={service} state=stopped"
            )
            yield
        finally:
            # Same immutable container ID, even when assertions inside the test fail.
            docker("start", identity)
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                state = json.loads(docker("inspect", identity))[0]["State"]
                if (
                    state.get("Running")
                    and state.get("Health", {}).get("Status") == "healthy"
                ):
                    print(
                        f"task14_fault project={self.project} service={service} state=restored_healthy"
                    )
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError(f"owned {service} did not recover to healthy")


@pytest.fixture
def owned_services():
    if os.getenv("TASK14_RUN_OWNED_FAULTS") != "1":
        pytest.skip("explicit TASK14_RUN_OWNED_FAULTS=1 required")
    project = os.environ.get("TASK14_OWNED_COMPOSE_PROJECT", "")
    assert re.fullmatch(r"evidencesoc-task14-[a-z0-9-]+", project), (
        "explicit owned Task14 project required"
    )
    assert "DATABASE_URL" in os.environ and "OPENSEARCH_URL" in os.environ
    settings = Settings(_env_file=None)
    assert urlsplit(settings.database_url).path.startswith("/task14_faults_"), (
        "dedicated Task14 fault database required"
    )
    owned = OwnedServices(project, settings)
    for service in ("postgres", "opensearch"):
        owned.container(service)
    return owned
