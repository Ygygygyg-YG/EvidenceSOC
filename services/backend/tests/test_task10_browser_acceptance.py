"""Operator runner contracts; no PostgreSQL, OpenSearch or web process required."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts" / "task10_browser_acceptance.py"


def load_runner():
    assert SCRIPT.is_file(), "A tracked browser acceptance runner is required"
    spec = importlib.util.spec_from_file_location("task10_browser_acceptance", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def environment(tmp_path):
    knowledge = tmp_path / "knowledge"
    knowledge.mkdir(exist_ok=True)
    return {
        "TASK10_POSTGRES_ADMIN_URL": "postgresql://operator:private@127.0.0.1:5432/postgres",
        "OPENSEARCH_URL": "http://127.0.0.1:9200",
        "RAG_DATA_DIRECTORY": str(knowledge),
    }


def test_missing_explicit_inputs_fail_without_loading_dotenv(tmp_path):
    runner = load_runner()
    with pytest.raises(ValueError, match="TASK10_POSTGRES_ADMIN_URL"):
        runner.RunConfig.from_inputs(
            ROOT, tmp_path, "production", 8018, 3018, "test_a", {}
        )


def test_unique_resources_and_runtime_environment_override_inherited_settings(tmp_path):
    runner = load_runner()
    env = environment(tmp_path)
    env.update(
        {"DATABASE_URL": "postgresql://do-not-use", "DEEPSEEK_API_KEY": "private-key"}
    )
    config = runner.RunConfig.from_inputs(
        ROOT, tmp_path, "production", 8018, 3018, "test_a", env
    )
    child = config.child_environment(env)
    assert config.database_name == "task10_browser_test_a"
    assert config.index_name == "task10-browser-test-a"
    assert child["DATABASE_URL"].endswith("/task10_browser_test_a")
    assert (
        child["BACKEND_URL"]
        == child["TASK10_LIVE_ISOLATED_BACKEND"]
        == "http://127.0.0.1:8018"
    )
    assert (
        child["FRONTEND_ORIGIN"]
        == child["PLAYWRIGHT_BASE_URL"]
        == "http://127.0.0.1:3018"
    )
    assert child["LLM_MODE"] == "fixture"
    assert child["DEMO_SESSION_ENABLED"] == "true"
    assert "DEEPSEEK_API_KEY" not in child


@pytest.mark.parametrize("run_id", ["../unsafe", "main;drop", "", "a" * 49])
def test_destructive_resource_names_are_bounded_and_validated(tmp_path, run_id):
    runner = load_runner()
    with pytest.raises(ValueError, match="run-id"):
        runner.RunConfig.from_inputs(
            ROOT, tmp_path, "production", 8018, 3018, run_id, environment(tmp_path)
        )


def test_occupied_port_fails_without_taking_over_process():
    import socket

    runner = load_runner()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        with pytest.raises(ValueError, match="occupied"):
            runner.require_free_port(listener.getsockname()[1])


def test_dotenv_is_rejected_by_presence_without_reading_it(tmp_path):
    runner = load_runner()
    (tmp_path / "apps" / "web").mkdir(parents=True)
    (tmp_path / "apps" / "web" / ".env.local").write_text("SECRET=private")
    with pytest.raises(ValueError, match="dotenv"):
        runner.require_explicit_environment(tmp_path)


def test_expiry_helper_refuses_an_unowned_database_before_connecting(monkeypatch):
    runner = load_runner()
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql://operator:private@127.0.0.1:5432/evidencesoc"
    )
    with pytest.raises(ValueError, match="owned"):
        runner.expire_owned_plan("test_a", "RP-test")


@pytest.mark.parametrize(
    "suffix", ["?dbname=existing", "?host=elsewhere", "?service=other", "#unexpected"]
)
def test_connection_targets_cannot_be_overridden_with_url_options(tmp_path, suffix):
    runner = load_runner()
    env = environment(tmp_path)
    env["TASK10_POSTGRES_ADMIN_URL"] += suffix
    with pytest.raises(ValueError, match="query|fragment"):
        runner.RunConfig.from_inputs(
            ROOT, tmp_path, "production", 8018, 3018, "test_a", env
        )


def test_expiry_helper_rejects_database_query_redirection_before_connecting(
    monkeypatch,
):
    runner = load_runner()
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://operator:private@127.0.0.1:5432/task10_browser_test_a?dbname=existing",
    )
    with pytest.raises(ValueError, match="query"):
        runner.expire_owned_plan("test_a", "RP-test")


def test_failed_build_prevents_browser_start(tmp_path):
    runner = load_runner()
    config = runner.RunConfig.from_inputs(
        ROOT, tmp_path, "production", 8018, 3018, "test_a", environment(tmp_path)
    )
    commands = []

    def run(name, command):
        commands.append(name)
        if name == "build":
            raise RuntimeError("build failed")

    with pytest.raises(RuntimeError, match="build failed"):
        runner.run_browser_commands(config, run, ["pnpm"])
    assert commands == ["build"]


def test_cleanup_failure_does_not_prevent_remaining_owned_resources():
    runner = load_runner()
    actions = []
    receipt = {"accepted": True, "cleanup": {}}

    def failed_index():
        actions.append("index")
        raise RuntimeError("simulated deletion failure")

    failure = runner.run_cleanup_steps(
        receipt,
        [
            ("index_deleted", failed_index),
            ("database_deleted", lambda: actions.append("database")),
            ("api_port_closed", lambda: actions.append("port")),
        ],
    )
    assert isinstance(failure, RuntimeError)
    assert actions == ["index", "database", "port"]
    assert receipt["accepted"] is False
    assert receipt["cleanup"]["index_deleted"] is False
    assert receipt["cleanup"]["database_deleted"] is True
    assert receipt["cleanup"]["api_port_closed"] is True


def test_dev_and_production_commands_run_all_tests_once_with_one_worker(tmp_path):
    runner = load_runner()
    for mode, expected in [("dev", ["browser"]), ("production", ["build", "browser"])]:
        config = runner.RunConfig.from_inputs(
            ROOT, tmp_path, mode, 8018, 3018, mode, environment(tmp_path)
        )
        commands = []
        runner.run_browser_commands(
            config,
            lambda name, command, commands=commands: commands.append((name, command)),
            ["node", "pnpm.cjs"],
        )
        assert [name for name, _ in commands] == expected
        assert "--workers=1" in commands[-1][1]
        assert "--retries=0" in commands[-1][1]


def test_report_gates_reject_skips_flakes_and_missing_real_scenarios():
    runner = load_runner()
    with pytest.raises(ValueError, match="browser"):
        runner.validate_browser_report(
            {"stats": {"expected": 1, "skipped": 1, "unexpected": 0, "flaky": 0}}
        )
