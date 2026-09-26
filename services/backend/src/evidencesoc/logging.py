"""JSON logging with one redaction boundary for application and library logs."""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any
from urllib.parse import (
    parse_qsl,
    quote,
    quote_plus,
    unquote,
    unquote_plus,
    urlsplit,
    urlunsplit,
)

import structlog
from pydantic import BaseModel, SecretBytes, SecretStr
from structlog.typing import Processor

REDACTED = "[REDACTED]"
_registered_secrets: set[str] = set()
_URL = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s<>\"']+", re.IGNORECASE)
_BEARER = re.compile(r"\b(Bearer|Basic)\s+[^\s,;\"'<>]+", re.IGNORECASE)
_API_KEY = re.compile(r"\bsk-[a-z0-9_-]+", re.IGNORECASE)
_CREDENTIAL_HEADER = re.compile(
    r"\b((?:set[-_ ]?)?cookie|(?:proxy[-_ ]?)?authorization)"
    r"[\"']?\s*[:=]\s*[^\r\n]+",
    re.IGNORECASE,
)
_ASSIGNMENT = re.compile(
    r"(?P<key>\b[a-z][a-z0-9_ -]*?)[\"']?\s*[:=]\s*"
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;&}\]\"']+)",
    re.IGNORECASE,
)


def _sensitive_key(key: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
    return normalized in {
        "authorization",
        "proxyauthorization",
        "cookie",
        "setcookie",
        "passwd",
        "pwd",
        "credential",
        "credentials",
    } or normalized.endswith(
        (
            "apikey",
            "modelkey",
            "password",
            "secret",
            "token",
            "credential",
            "credentials",
        )
    )


def _register_string(value: str) -> None:
    if value:
        _registered_secrets.update((value, quote(value, safe=""), quote_plus(value)))


def register_secrets(values: Any) -> None:
    """Register configured secret values without reading configuration files.

    Settings objects, mappings, and SecretStr/SecretBytes are accepted. URL
    passwords are also registered so library messages with an unlabelled
    credential still pass through the same redaction boundary.
    """
    if isinstance(values, (SecretStr, SecretBytes)):
        raw = values.get_secret_value()
        _register_string(
            raw.decode(errors="replace") if isinstance(raw, bytes) else raw
        )
    elif isinstance(values, BaseModel):
        register_secrets(values.model_dump())
    elif isinstance(values, Mapping):
        for key, value in values.items():
            if isinstance(value, str):
                if _sensitive_key(key):
                    _register_string(value)
                _register_url_secrets(value)
            else:
                register_secrets(value)
    elif isinstance(values, (list, tuple, set, frozenset)):
        for value in values:
            register_secrets(value)
    elif isinstance(values, str):
        _register_string(values)
        _register_url_secrets(values)


def _register_url_secrets(value: str) -> None:
    for match in _URL.finditer(value):
        try:
            url = urlsplit(match.group())
            password = url.password
        except ValueError:
            continue
        if password:
            _register_string(unquote(password))
        for key, secret in parse_qsl(url.query):
            if _sensitive_key(key):
                _register_string(secret)


def _redact_url(match: re.Match[str]) -> str:
    original = match.group()
    try:
        url = urlsplit(original)
        netloc = url.netloc
        if "@" in netloc:
            netloc = f"{REDACTED}@{netloc.rsplit('@', 1)[1]}"
        query_parts = []
        for part in url.query.split("&"):
            key, separator, value = part.partition("=")
            if _sensitive_key(unquote_plus(key)):
                value = REDACTED
            query_parts.append(f"{key}{separator}{value}")
        return urlunsplit(
            (url.scheme, netloc, url.path, "&".join(query_parts), url.fragment)
        )
    except ValueError:
        return REDACTED


def _redact_text(value: str) -> str:
    for secret in sorted(_registered_secrets, key=len, reverse=True):
        value = value.replace(secret, REDACTED)
    value = _URL.sub(_redact_url, value)
    value = _CREDENTIAL_HEADER.sub(lambda match: f"{match.group(1)}: {REDACTED}", value)
    value = _BEARER.sub(lambda match: f"{match.group(1)} {REDACTED}", value)
    value = _API_KEY.sub(REDACTED, value)

    def replace_assignment(match: re.Match[str]) -> str:
        key = match.group("key")
        # A prose prefix can precede a field, e.g. 'failed with api_key=...'.
        if _sensitive_key(key) or _sensitive_key(key.rsplit(" ", 1)[-1]):
            return f"{key}={REDACTED}"
        return match.group()

    return _ASSIGNMENT.sub(replace_assignment, value)


def redact(value: Any) -> Any:
    """Return a sanitized JSON-compatible copy, including nested log values."""
    if isinstance(value, (SecretStr, SecretBytes)):
        return REDACTED
    if isinstance(value, BaseException):
        return {"error_type": type(value).__name__}
    if isinstance(value, BaseModel):
        return redact(value.model_dump())
    if isinstance(value, Mapping):
        return {
            _redact_text(str(key)): REDACTED if _sensitive_key(key) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set, frozenset)):
        return [redact(item) for item in value]
    if isinstance(value, bytes):
        return _redact_text(value.decode(errors="replace"))
    if isinstance(value, str):
        return _redact_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _redact_text(str(value))


def redact_processor(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> dict[str, Any]:
    """Suppress exception contents and sanitize the complete rendered event."""
    event = dict(event_dict)
    exception = event.pop("exception", None)
    exc_info = event.pop("exc_info", None)
    if isinstance(exc_info, tuple) and len(exc_info) > 1:
        exception = exc_info[1]
    elif exc_info is True:
        exception = sys.exc_info()[1]
    if isinstance(exception, BaseException):
        event["error_type"] = type(exception).__name__
    for key in ("stack", "stack_info", "stacktrace", "traceback"):
        event.pop(key, None)
    return redact(event)


def configure_logging() -> None:
    """Route structlog and existing library loggers through sanitized JSON."""
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
    ]
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=[*shared_processors, structlog.stdlib.ExtraAdder()],
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            redact_processor,
            structlog.processors.JSONRenderer(ensure_ascii=False),
        ],
        keep_exc_info=False,
        keep_stack_info=False,
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    for previous in root.handlers[:]:
        root.removeHandler(previous)
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    for logger in logging.Logger.manager.loggerDict.values():
        if isinstance(logger, logging.Logger):
            logger.handlers.clear()
            logger.propagate = True
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            *shared_processors,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )
