"""Run one owned, serial Task10 browser acceptance without loading dotenv files.

Required explicit environment: TASK10_POSTGRES_ADMIN_URL, OPENSEARCH_URL,
RAG_DATA_DIRECTORY. Run using the backend Python environment. No credentials are
accepted on the command line or copied into the acceptance receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
RUN_ID = re.compile(r"^[a-z0-9][a-z0-9_]{0,31}$")


def validated_run_id(run_id: str) -> str:
    if not RUN_ID.fullmatch(run_id):
        raise ValueError(
            "run-id must contain 1-32 lowercase letters, digits or underscores"
        )
    return run_id


def require_explicit_environment(root: Path) -> None:
    for directory in (root, root / "apps" / "web", root / "services" / "backend"):
        # A tracked .env.example is documentation, never a dotenv input.
        if any(path.name != ".env.example" for path in directory.glob(".env*")):
            raise ValueError("Remove implicit dotenv inputs from the isolated checkout")


def require_free_port(port: int) -> None:
    if not 1024 <= port <= 65535:
        raise ValueError("Ports must be between 1024 and 65535")
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as error:
            raise ValueError("Requested acceptance port is occupied") from error


def local_url(value: str, schemes: set[str], name: str) -> str:
    parsed = urlsplit(value.replace("postgresql+psycopg://", "postgresql://", 1))
    if parsed.query or parsed.fragment:
        raise ValueError(f"{name} query and fragment options are forbidden")
    if parsed.scheme not in schemes or parsed.hostname not in {
        "127.0.0.1",
        "localhost",
        "::1",
    }:
        raise ValueError(f"{name} must identify a local explicit service")
    return urlunsplit(parsed)


@dataclass(frozen=True)
class RunConfig:
    root: Path
    artifacts_root: Path
    web_mode: str
    api_port: int
    web_port: int
    run_id: str
    admin_url: str
    search_url: str
    knowledge: Path

    @classmethod
    def from_inputs(cls, root, artifacts, mode, api_port, web_port, run_id, env):
        validated_run_id(run_id)
        if mode not in {"dev", "production"}:
            raise ValueError("web mode must be dev or production")
        for name in (
            "TASK10_POSTGRES_ADMIN_URL",
            "OPENSEARCH_URL",
            "RAG_DATA_DIRECTORY",
        ):
            if not env.get(name, "").strip():
                raise ValueError(f"Missing required explicit environment: {name}")
        if api_port == web_port or any(
            not 1024 <= port <= 65535 for port in (api_port, web_port)
        ):
            raise ValueError("Two distinct local ports in 1024-65535 are required")
        knowledge = Path(env["RAG_DATA_DIRECTORY"]).resolve()
        if not knowledge.is_dir():
            raise ValueError("RAG_DATA_DIRECTORY must be a prepared local directory")
        return cls(
            Path(root).resolve(),
            Path(artifacts).resolve(),
            mode,
            api_port,
            web_port,
            run_id,
            local_url(env["TASK10_POSTGRES_ADMIN_URL"], {"postgresql"}, "PostgreSQL"),
            local_url(env["OPENSEARCH_URL"], {"http", "https"}, "OpenSearch"),
            knowledge,
        )

    @property
    def database_name(self):
        return "task10_browser_" + self.run_id

    @property
    def index_name(self):
        return "task10-browser-" + self.run_id.replace("_", "-")

    @property
    def database_url(self):
        parsed = urlsplit(self.admin_url)
        return urlunsplit(
            parsed._replace(scheme="postgresql+psycopg", path="/" + self.database_name)
        )

    @property
    def output(self):
        return self.artifacts_root / ("frontend-" + self.run_id)

    def child_environment(self, source):
        result = {
            key: value
            for key, value in source.items()
            if not key.upper().startswith(("DEEPSEEK_", "OPENAI_", "ANTHROPIC_"))
            and key.upper() != "TASK10_POSTGRES_ADMIN_URL"
        }
        result.update(
            {
                "DATABASE_URL": self.database_url,
                "OPENSEARCH_URL": self.search_url,
                "OPENSEARCH_INDEX": self.index_name,
                "RAG_DATA_DIRECTORY": str(self.knowledge),
                "LLM_MODE": "fixture",
                "DEMO_SESSION_ENABLED": "true",
                "FRONTEND_ORIGIN": f"http://127.0.0.1:{self.web_port}",
                "PLAYWRIGHT_BASE_URL": f"http://127.0.0.1:{self.web_port}",
                "BACKEND_URL": f"http://127.0.0.1:{self.api_port}",
                "TASK10_LIVE_ISOLATED_BACKEND": f"http://127.0.0.1:{self.api_port}",
                "TASK10_ACCEPTANCE_RUN_ID": self.run_id,
                "TASK10_ACCEPTANCE_ROOT": str(self.root),
                "TASK10_ACCEPTANCE_PYTHON": sys.executable,
                "PLAYWRIGHT_WEB_MODE": self.web_mode,
                "PLAYWRIGHT_JSON_OUTPUT_FILE": str(
                    self.output / "playwright-report.json"
                ),
                "CI": "1",
                "PYTHONUTF8": "1",
                "PYTHONIOENCODING": "utf-8",
                "PYTHONPATH": os.pathsep.join(
                    (str(self.root / "services/backend/src"), str(self.root))
                ),
                "HF_HUB_OFFLINE": "1",
                "TRANSFORMERS_OFFLINE": "1",
                "HF_HUB_DISABLE_TELEMETRY": "1",
            }
        )
        result.pop("NODE_ENV", None)
        return result


def run_browser_commands(config, run, pnpm):
    if config.web_mode == "production":
        run("build", [*pnpm, "--dir", "apps/web", "build"])
    run(
        "browser",
        [
            *pnpm,
            "--dir",
            "apps/web",
            "exec",
            "playwright",
            "test",
            "--workers=1",
            "--retries=0",
            "--reporter=list,json",
            "--output",
            str(config.output / "test-results"),
        ],
    )


def validate_browser_report(report):
    stats = report.get("stats", {})
    if not stats.get("expected") or any(
        stats.get(key) != 0 for key in ("skipped", "unexpected", "flaky")
    ):
        raise ValueError("Incomplete or unsuccessful browser acceptance report")
    tests = []

    def visit(suite):
        for spec in suite.get("specs", []):
            tests.append(spec.get("title", ""))
        for child in suite.get("suites", []):
            visit(child)

    visit(report)
    for expected in ("人工批准与模拟验证", "人工拒绝并停止处置", "真实过期方案续办"):
        if not any(expected in title for title in tests):
            raise ValueError("Required real browser scenario was not executed")
    return stats


def verify_knowledge_inputs(directory):
    from evidencesoc.rag.embeddings import _verify_model
    from evidencesoc.rag.ingest_attack import (
        PINNED_ATTACK_VERSION,
        PINNED_STIX_SHA256,
        PINNED_STIX_URL,
    )
    from evidencesoc.rag.models import SourceManifest

    source = directory / "enterprise-attack-19.2.json"
    manifest_path = directory / "enterprise-attack-19.2.manifest.json"
    manifest = SourceManifest.model_validate_json(
        manifest_path.read_text(encoding="utf-8")
    )
    if (
        hashlib.sha256(source.read_bytes()).hexdigest() != PINNED_STIX_SHA256
        or manifest.version != PINNED_ATTACK_VERSION
        or manifest.sha256 != PINNED_STIX_SHA256
        or manifest.source_uri != PINNED_STIX_URL
    ):
        raise ValueError("Pinned offline knowledge inputs do not match")
    _verify_model(directory / "model")
    return {
        name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
        for name in (
            "enterprise-attack-19.2.json",
            "enterprise-attack-19.2.manifest.json",
            "model/manifest.json",
        )
    }


def run_cleanup_steps(receipt, steps):
    failure = None
    for label, operation in steps:
        try:
            operation()
            receipt["cleanup"][label] = True
        except Exception as error:  # noqa: BLE001 -- record safe types and attempt every owned cleanup.
            failure = failure or error
            receipt["cleanup"][label] = False
            receipt["cleanup"][label + "_failure_type"] = type(error).__name__
            receipt["accepted"] = False
    return failure


def expire_owned_plan(run_id: str, plan_id: str) -> None:
    validated_run_id(run_id)
    database = os.environ.get("DATABASE_URL", "")
    if urlsplit(database).path != "/task10_browser_" + run_id:
        raise ValueError("Expiry setup requires the exact owned acceptance database")
    local_url(database, {"postgresql"}, "PostgreSQL")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", plan_id):
        raise ValueError("Invalid plan ID")
    from evidencesoc.persistence.database import (
        create_database_engine,
        create_session_factory,
    )
    from evidencesoc.persistence.tables import IncidentTable, ResponsePlanTable
    from sqlalchemy import select

    engine = create_database_engine(database)
    try:
        with create_session_factory(engine).begin() as session:
            row = session.execute(
                select(ResponsePlanTable, IncidentTable)
                .join(
                    IncidentTable,
                    IncidentTable.incident_id == ResponsePlanTable.incident_id,
                )
                .where(ResponsePlanTable.response_plan_id == plan_id)
            ).first()
            if row is None or not row[1].alert_id.startswith(f"AL-RENEW-{run_id}-"):
                raise ValueError("Expiry setup rejected a plan outside this owned case")
            row[0].expires_at = row[0].created_at + timedelta(milliseconds=1)
    finally:
        engine.dispose()


def stop_owned_process(process):
    if process is None or process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        import signal

        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            import signal

            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=10)


def pnpm_command():
    command = shutil.which("pnpm")
    if not command:
        raise ValueError("pnpm must be available on PATH")
    # Python shell=False can execute neither .cmd nor .ps1 on Windows. Invoke
    # Corepack's JavaScript launcher via Node instead, retaining packageManager.
    if os.name == "nt":
        node = shutil.which("node")
        corepack = Path(command).parent / "node_modules/corepack/dist/pnpm.js"
        if not node or not corepack.is_file():
            raise ValueError("A Node/Corepack pnpm installation is required on Windows")
        return [node, str(corepack)]
    return [command]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--artifacts-root", type=Path)
    parser.add_argument(
        "--web-mode", choices=["dev", "production"], default="production"
    )
    parser.add_argument("--api-port", type=int, default=8018)
    parser.add_argument("--web-port", type=int, default=3018)
    parser.add_argument(
        "--run-id",
        default=datetime.now(UTC).strftime("%Y%m%d_%H%M%S_") + uuid4().hex[:8],
    )
    parser.add_argument("--expire-plan-id", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    require_explicit_environment(args.root)
    if args.expire_plan_id:
        expire_owned_plan(args.run_id, args.expire_plan_id)
        print("Expired the owned test plan for browser acceptance")
        return 0
    if args.artifacts_root is None:
        raise ValueError("--artifacts-root is required for a new acceptance run")
    config = RunConfig.from_inputs(
        args.root,
        args.artifacts_root,
        args.web_mode,
        args.api_port,
        args.web_port,
        args.run_id,
        os.environ,
    )
    return execute(config, os.environ)


def execute(config: RunConfig, source_environment):
    import httpx
    import psycopg
    from psycopg import sql

    require_free_port(config.api_port)
    require_free_port(config.web_port)
    for name in (
        "enterprise-attack-19.2.json",
        "enterprise-attack-19.2.manifest.json",
        "model",
    ):
        if not (config.knowledge / name).exists():
            raise ValueError("Prepared offline RAG sources and model are required")
    knowledge_binding = verify_knowledge_inputs(config.knowledge)
    config.output.mkdir(parents=True, exist_ok=False)
    env = config.child_environment(source_environment)
    pnpm = pnpm_command()
    receipt = {
        "schema_version": 1,
        "run_id": config.run_id,
        "web_mode": config.web_mode,
        "llm_mode": "fixture",
        "started_at": datetime.now(UTC).isoformat(),
        "database_name": config.database_name,
        "index_name": config.index_name,
        "api_port": config.api_port,
        "web_port": config.web_port,
        "reuse_existing_server": False,
        "workers": 1,
        "commands": [],
        "accepted": False,
        "cleanup": {},
    }
    receipt["knowledge_inputs_sha256"] = knowledge_binding
    secret_values = [config.admin_url, config.database_url]
    for url in (config.admin_url, config.search_url):
        password = urlsplit(url).password
        if password:
            secret_values.append(password)

    def redacted(line):
        for value in secret_values:
            line = line.replace(value, "[REDACTED]")
        return line

    def run(name, command):
        print(f"frontend {name}: started", flush=True)
        started = time.monotonic()
        with (config.output / f"{name}.log").open("x", encoding="utf-8") as log:
            process = subprocess.Popen(
                command,
                cwd=config.root,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                start_new_session=os.name != "nt",
            )
            try:
                for line in process.stdout:
                    log.write(redacted(line))
                    log.flush()
                code = process.wait()
            finally:
                stop_owned_process(process)
        receipt["commands"].append(
            {
                "name": name,
                "exit_code": code,
                "seconds": round(time.monotonic() - started, 3),
            }
        )
        print(f"frontend {name}: exit {code}", flush=True)
        if code:
            raise RuntimeError(f"Acceptance step failed: {name}")

    api = None
    api_log = None
    created_database = False
    created_index = False
    failure = None
    try:
        receipt["source_commit"] = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=config.root, text=True
        ).strip()
        tracked = subprocess.check_output(
            [
                "git",
                "ls-files",
                "apps/web/src",
                "apps/web/e2e",
                "apps/web/playwright.config.ts",
                "services/backend/src",
                "scripts/task10_browser_acceptance.py",
            ],
            cwd=config.root,
            text=True,
        ).splitlines()
        tracked.extend(
            [
                "scripts/task10_browser_acceptance.py",
                "apps/web/e2e/response-renewal-live.spec.ts",
            ]
        )
        receipt["source_sha256"] = {
            name: hashlib.sha256((config.root / name).read_bytes()).hexdigest()
            for name in sorted(set(tracked))
            if (config.root / name).is_file()
        }
        with psycopg.connect(
            config.admin_url, autocommit=True, connect_timeout=5
        ) as admin:
            admin.execute(
                sql.SQL("CREATE DATABASE {}").format(
                    sql.Identifier(config.database_name)
                )
            )
        created_database = True
        with psycopg.connect(
            config.database_url.replace("postgresql+psycopg://", "postgresql://", 1),
            autocommit=True,
        ) as owned:
            owned.execute("CREATE EXTENSION IF NOT EXISTS vector")
        with httpx.Client(
            base_url=config.search_url, trust_env=False, timeout=15
        ) as search:
            exists = search.head("/" + config.index_name)
            if exists.status_code != 404:
                raise ValueError(
                    "Acceptance index already exists or cannot be verified absent"
                )
            template = json.loads(
                (
                    config.root / "infra/opensearch/security-events-template.json"
                ).read_text(encoding="utf-8")
            )
            created = search.put("/" + config.index_name, json=template["template"])
            created.raise_for_status()
        created_index = True
        run(
            "migrations",
            [
                sys.executable,
                "-m",
                "alembic",
                "-c",
                "services/backend/alembic.ini",
                "upgrade",
                "head",
            ],
        )
        run("knowledge", [sys.executable, "-m", "evidencesoc.rag.cli", "prepare"])
        api_log = (config.output / "backend.log").open("x", encoding="utf-8")
        api = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "evidencesoc.main:app",
                "--app-dir",
                str(config.root / "services/backend/src"),
                "--host",
                "127.0.0.1",
                "--port",
                str(config.api_port),
                "--no-access-log",
                "--loop",
                "asyncio",
            ],
            cwd=config.root,
            env=env,
            stdout=api_log,
            stderr=subprocess.STDOUT,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            start_new_session=os.name != "nt",
        )
        receipt["backend_pid"] = api.pid
        with httpx.Client(
            base_url=env["BACKEND_URL"], timeout=3, trust_env=False
        ) as client:
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                if api.poll() is not None:
                    raise RuntimeError("Owned backend exited before readiness")
                try:
                    if client.get("/health/ready").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.5)
            else:
                raise RuntimeError("Owned backend readiness timed out")
        run(
            "seed",
            [
                sys.executable,
                str(config.root / "scripts/seed-task10.py"),
                "--api-url",
                env["BACKEND_URL"],
            ],
        )
        seed = json.loads(
            (config.output / "seed.log").read_text(encoding="utf-8").splitlines()[-1]
        )
        env["TASK10_LIVE_SEED_ALERT_ID"] = seed["alert_id"]
        receipt["seed_alert_id"] = seed["alert_id"]
        run_browser_commands(config, run, pnpm)
        receipt["browser_stats"] = validate_browser_report(
            json.loads(
                (config.output / "playwright-report.json").read_text(encoding="utf-8")
            )
        )
        after = {
            name: hashlib.sha256((config.root / name).read_bytes()).hexdigest()
            for name in receipt["source_sha256"]
        }
        receipt["source_unchanged"] = after == receipt["source_sha256"]
        receipt["knowledge_inputs_unchanged"] = (
            verify_knowledge_inputs(config.knowledge) == knowledge_binding
        )
        if not receipt["source_unchanged"] or not receipt["knowledge_inputs_unchanged"]:
            raise RuntimeError("Acceptance inputs changed during execution")
        receipt["accepted"] = True
    except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 -- preserve failure evidence without leaking DSNs.
        # Exception strings and connection libraries can contain DSNs.
        failure = error
        receipt["failure_type"] = type(error).__name__
    finally:

        def stop_backend():
            stop_owned_process(api)
            if api is not None and api.poll() is None:
                raise RuntimeError("Owned backend is still running")

        def delete_index():
            with httpx.Client(
                base_url=config.search_url, trust_env=False, timeout=15
            ) as search:
                deleted = search.delete("/" + config.index_name)
                deleted.raise_for_status()

        def delete_database():
            with psycopg.connect(
                config.admin_url, autocommit=True, connect_timeout=5
            ) as admin:
                admin.execute(
                    sql.SQL("DROP DATABASE {} WITH (FORCE)").format(
                        sql.Identifier(config.database_name)
                    )
                )

        steps = [("backend_stopped", stop_backend)]
        if api_log:
            steps.append(("backend_log_closed", api_log.close))
        if created_index:
            steps.append(("index_deleted", delete_index))
        if created_database:
            steps.append(("database_deleted", delete_database))
        steps.extend(
            [
                ("api_port_closed", lambda: require_free_port(config.api_port)),
                ("web_port_closed", lambda: require_free_port(config.web_port)),
            ]
        )
        cleanup_failure = run_cleanup_steps(receipt, steps)
        failure = failure or cleanup_failure
        backend_log_path = config.output / "backend.log"
        if backend_log_path.is_file():
            content = backend_log_path.read_text(encoding="utf-8", errors="replace")
            safe_content = redacted(content)
            if safe_content != content:
                backend_log_path.write_text(safe_content, encoding="utf-8")
        receipt["finished_at"] = datetime.now(UTC).isoformat()
        receipt["artifact_sha256"] = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in config.output.iterdir()
            if p.is_file()
        }
        (config.output / "acceptance.json").write_text(
            json.dumps(receipt, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    print(f"Acceptance receipt: {config.output / 'acceptance.json'}", flush=True)
    if failure:
        print(
            f"Acceptance failed ({type(failure).__name__}); inspect redacted step logs.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as error:
        print(
            f"Acceptance configuration failed ({type(error).__name__}). Check required inputs and --help.",
            file=sys.stderr,
        )
        raise SystemExit(2) from None
