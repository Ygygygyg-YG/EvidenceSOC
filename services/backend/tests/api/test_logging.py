from __future__ import annotations

import importlib
import importlib.util
import json
import logging

import pytest
import structlog
from pydantic import BaseModel, SecretStr


def logging_module():
    assert importlib.util.find_spec("evidencesoc.logging") is not None, (
        "structured logging redaction module is required"
    )
    return importlib.import_module("evidencesoc.logging")


@pytest.mark.parametrize(
    "key",
    [
        "Authorization",
        "Proxy-Authorization",
        "Cookie",
        "Set-Cookie",
        "API-Key",
        "X-API-KEY",
        "api_key",
        "password",
        "PASS-WORD",
        "passwd",
        "Model-Key",
        "deepseek_api_key",
        "client-secret",
        "access_token",
        "Refresh-Token",
        "credentials",
        "credential",
        "database_credentials",
        "provider-secret",
        "session-token",
    ],
)
def test_sensitive_fields_are_redacted_at_every_depth(key):
    module = logging_module()
    original = {"nested": [{key: "never-print-me", "count": 3}]}
    assert module.redact(original) == {"nested": [{key: "[REDACTED]", "count": 3}]}
    assert original["nested"][0][key] == "never-print-me"


def test_secret_objects_and_exceptions_do_not_reveal_content():
    module = logging_module()
    result = module.redact(
        {"items": [SecretStr("never-print-me"), ValueError("never-print-me")]}
    )
    assert result == {"items": ["[REDACTED]", {"error_type": "ValueError"}]}


@pytest.mark.parametrize(
    "message",
    [
        "Authorization: Bearer never-print-me",
        "Bearer never-print-me",
        "Cookie: session=never-print-me; Path=/",
        "Set-Cookie: session=never-print-me; HttpOnly",
        "api_key=never-print-me",
        "API-Key: never-print-me",
        'password="never-print-me"',
        "password = 'never-print-me'",
        '{"deepseek_api_key": "never-print-me"}',
        "request failed for sk-never-print-me",
        "model-key=never-print-me",
        "client_secret: never-print-me",
        "credentials=never-print-me",
        'Authorization: Digest username="never-print-me", response="never-print-me"',
        "Proxy-Authorization: Basic bmV2ZXItcHJpbnQtbWU= never-print-me",
    ],
)
def test_free_text_credentials_are_redacted(message):
    result = logging_module().redact({"nested": [message]})
    assert "never-print-me" not in json.dumps(result)
    assert "[REDACTED]" in json.dumps(result)


def test_url_credentials_and_secret_query_values_are_redacted():
    result = logging_module().redact(
        "connect postgresql+psycopg://alice:never-print-me@localhost/db?"
        "access_token=never-print-me&limit=7 and "
        "https://api.example.test/v1?API-Key=never-print-me&model=fixture"
    )
    assert "alice" not in result
    assert "never-print-me" not in result
    assert "localhost/db" in result
    assert "limit=7" in result
    assert "model=fixture" in result


def test_registered_secret_values_are_removed_from_arbitrary_messages():
    module = logging_module()
    module.register_secrets(
        {
            "model": SecretStr("unlabelled-real-model-value"),
            "database_url": "postgresql://user:db-secret-value@localhost/db",
        }
    )
    result = module.redact(
        {"arbitrary": ["failed with unlabelled-real-model-value", "db-secret-value"]}
    )
    assert "unlabelled-real-model-value" not in json.dumps(result)
    assert "db-secret-value" not in json.dumps(result)


def test_registering_settings_preserves_safe_values_and_registers_plain_secrets():
    class ExampleSettings(BaseModel):
        llm_mode: str = "fixture"
        deepseek_api_key: SecretStr = SecretStr("settings-unlabelled-value")

    module = logging_module()
    module.register_secrets(ExampleSettings())
    module.register_secrets(["bare-unlabelled-value"])
    assert module.redact("fixture") == "fixture"
    assert module.redact("settings-unlabelled-value") == "[REDACTED]"
    assert module.redact("bare-unlabelled-value") == "[REDACTED]"


def test_urlencoded_values_and_nested_secret_bytes_are_redacted():
    module = logging_module()
    module.register_secrets({"api_key": "private value+symbol"})
    result = module.redact(
        {
            "items": (b"password=never-print-me", "private%20value%2Bsymbol"),
            "url": "https://api.example/?%61pi%5fkey=never-print-me&count=5",
        }
    )
    assert "never-print-me" not in json.dumps(result)
    assert "private" not in json.dumps(result)
    assert "count=5" in result["url"]


def test_configured_url_secrets_are_registered_with_literal_plus_password():
    module = logging_module()
    module.register_secrets(
        {
            "database_url": "postgresql://user:url+password@localhost/db?"
            "access_token=url-query-private-value"
        }
    )
    assert module.redact("url+password") == "[REDACTED]"
    assert module.redact("url-query-private-value") == "[REDACTED]"


def test_processor_replaces_exception_information_with_safe_type():
    module = logging_module()
    error = ValueError("never-print-me")
    event = {
        "event": "request_failed",
        "exc_info": (ValueError, error, None),
        "exception": error,
        "stack": "never-print-me",
        "stack_info": True,
    }
    result = module.redact_processor(None, "error", event)
    assert result["event"] == "request_failed"
    assert result["error_type"] == "ValueError"
    assert all(
        key not in result for key in ("exc_info", "exception", "stack", "stack_info")
    )
    assert "never-print-me" not in json.dumps(result)


def test_standard_and_structured_logs_use_the_same_redaction(capsys):
    module = logging_module()
    root = logging.getLogger()
    previous_handlers, previous_level = root.handlers[:], root.level
    named_states = {
        name: (logger.handlers[:], logger.level, logger.propagate, logger.disabled)
        for name, logger in logging.Logger.manager.loggerDict.items()
        if isinstance(logger, logging.Logger)
    }
    previous_structlog = structlog.get_config().copy()
    try:
        module.configure_logging()
        structlog.get_logger("app").info(
            "request_completed", nested={"Authorization": "never-print-me"}
        )
        logging.getLogger("httpx").warning(
            "request url=%s",
            "https://user:never-print-me@example.test/?token=never-print-me",
            extra={"credentials": "never-print-me"},
        )
        try:
            raise RuntimeError("never-print-me")
        except RuntimeError:
            logging.getLogger("dependency").exception("dependency_failed")
        output = capsys.readouterr().out
        events = [json.loads(line) for line in output.splitlines()]
        assert len(events) == 3
        assert all("never-print-me" not in json.dumps(event) for event in events)
        assert events[0]["nested"]["Authorization"] == "[REDACTED]"
        assert events[1]["credentials"] == "[REDACTED]"
        assert events[2]["error_type"] == "RuntimeError"
        assert "Traceback" not in output
        assert all("timestamp" in event and "level" in event for event in events)
    finally:
        for handler in root.handlers:
            if handler not in previous_handlers:
                handler.close()
        root.handlers = previous_handlers
        root.setLevel(previous_level)
        for name, state in named_states.items():
            logger = logging.getLogger(name)
            logger.handlers, logger.level, logger.propagate, logger.disabled = state
        structlog.configure(**previous_structlog)
