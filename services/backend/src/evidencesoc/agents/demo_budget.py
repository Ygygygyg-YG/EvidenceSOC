"""Durable budget enforcement at the demo model's HTTP transport boundary."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sqlite3
import ssl
from collections.abc import Iterator
from contextlib import closing, contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from pathlib import Path

import certifi
import httpx

DEMO_MODEL = "deepseek-flash"
DEMO_BASE_URL = "https://api.deepseek.com"
DEMO_MAX_OUTPUT_TOKENS = 4096

# Checked 2026-11-11 against DeepSeek's official pricing and model metadata.
# https://api-docs.deepseek.com/zh-cn/quick_start/pricing/
# https://api-docs.deepseek.com/zh-cn/api/list-models/
_MAX_INPUT_TOKENS = 1_048_576
_INPUT_RATE = 2  # Peak cache-miss micro-CNY per input token.
_OUTPUT_RATE = 8  # Peak micro-CNY per output token, including reasoning.
_MICRO_CNY = 1_000_000
_LIMIT = 3 * _MICRO_CNY
_APPLICATION_ID = 0x44454D4F
_RESPONSE_MODELS = {DEMO_MODEL, "deepseek-v4.1-flash", "deepseek-v4.1-flash-1017"}
_REQUEST_FIELDS = {
    "model",
    "messages",
    "max_tokens",
    "stream",
    "n",
    "thinking",
    "reasoning_effort",
    "temperature",
    "top_p",
    "response_format",
    "stop",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
}
_SAFE_ID = re.compile(r"[a-zA-Z0-9_.:-]{1,160}")

model_request_context: ContextVar[dict[str, str]] = ContextVar(
    "model_request_context",
    default={},  # noqa: B039 - callers bind context with set().
)


class DemoBudgetError(RuntimeError):
    """A demo request failed a transport or ledger safety check."""


@dataclass(frozen=True)
class DemoBudgetSummary:
    limit_cny: float
    spent_cny: float
    reserved_cny: float
    available_cny: float
    requests: int
    settled: int
    in_flight: int
    unknown: int
    blocked: bool


def _safe_id(value: object) -> str | None:
    if (
        isinstance(value, str)
        and _SAFE_ID.fullmatch(value)
        and not value.startswith("sk-")
    ):
        return value
    return None


class _Ledger:
    def __init__(self, path: Path):
        self.path = path.resolve()

    @contextmanager
    def _connect(self, mode: str = "rw") -> Iterator[sqlite3.Connection]:
        try:
            uri = f"{self.path.as_uri()}?mode={mode}"
            with closing(sqlite3.connect(uri, uri=True, timeout=1)) as db, db:
                if mode != "ro":
                    db.execute("PRAGMA synchronous=FULL")
                yield db
        except sqlite3.Error as exc:
            raise DemoBudgetError("Demo model budget ledger unavailable") from exc

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect("rwc") as db:
            db.execute("BEGIN IMMEDIATE")
            application_id = db.execute("PRAGMA application_id").fetchone()[0]
            if application_id == _APPLICATION_ID:
                db.execute("SELECT id FROM demo_model_requests LIMIT 1")
                return
            if (
                application_id
                or db.execute("SELECT 1 FROM sqlite_schema LIMIT 1").fetchone()
            ):
                raise DemoBudgetError("Path is already in use by a different database")
            db.execute("""
                CREATE TABLE demo_model_requests (
                    id INTEGER PRIMARY KEY,
                    reserved_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    finished_at TEXT,
                    status TEXT NOT NULL DEFAULT 'reserved'
                        CHECK (status IN ('reserved', 'settled', 'unknown')),
                    failure TEXT,
                    request_sha256 TEXT NOT NULL,
                    requested_model TEXT NOT NULL,
                    role TEXT,
                    incident_id TEXT,
                    model_call_id TEXT,
                    max_input_tokens INTEGER NOT NULL,
                    max_output_tokens INTEGER NOT NULL,
                    input_rate_micro_cny INTEGER NOT NULL,
                    output_rate_micro_cny INTEGER NOT NULL,
                    reserved_micro_cny INTEGER NOT NULL,
                    actual_micro_cny INTEGER,
                    http_status INTEGER,
                    response_model TEXT,
                    provider_request_id TEXT,
                    prompt_tokens INTEGER,
                    completion_tokens INTEGER,
                    CHECK (
                        (status = 'settled' AND actual_micro_cny IS NOT NULL
                            AND actual_micro_cny BETWEEN 0 AND reserved_micro_cny)
                        OR (status != 'settled' AND actual_micro_cny IS NULL)
                    )
                )
            """)
            db.execute(f"PRAGMA application_id={_APPLICATION_ID}")

    def reserve(self, max_tokens: int, request_sha256: str) -> int:
        amount = _MAX_INPUT_TOKENS * _INPUT_RATE + max_tokens * _OUTPUT_RATE
        context = model_request_context.get()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            spent, unresolved = db.execute("""
                SELECT COALESCE(SUM(actual_micro_cny), 0), COUNT(*) - COUNT(actual_micro_cny)
                FROM demo_model_requests
            """).fetchone()
            if unresolved:
                raise DemoBudgetError("Demo model budget has an unresolved request")
            if spent + amount > _LIMIT:
                raise DemoBudgetError(
                    "Request would exceed the 3 CNY demo model budget"
                )
            reservation = db.execute(
                """
                INSERT INTO demo_model_requests (
                    request_sha256, requested_model, role, incident_id, model_call_id,
                    max_input_tokens, max_output_tokens, input_rate_micro_cny,
                    output_rate_micro_cny, reserved_micro_cny
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_sha256,
                    DEMO_MODEL,
                    _safe_id(context.get("role")),
                    _safe_id(context.get("incident_id")),
                    _safe_id(context.get("model_call_id")),
                    _MAX_INPUT_TOKENS,
                    max_tokens,
                    _INPUT_RATE,
                    _OUTPUT_RATE,
                    amount,
                ),
            ).lastrowid
            assert reservation is not None
        return reservation

    def finish(
        self,
        reservation: int,
        *,
        failure: str | None = None,
        http_status: int | None = None,
        response_model: str | None = None,
        provider_request_id: str | None = None,
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
    ) -> None:
        charge = None
        if (
            failure is None
            and prompt_tokens is not None
            and completion_tokens is not None
        ):
            charge = prompt_tokens * _INPUT_RATE + completion_tokens * _OUTPUT_RATE
        with self._connect() as db:
            update = db.execute(
                """
                UPDATE demo_model_requests SET
                    finished_at=CURRENT_TIMESTAMP, status=?, failure=?, actual_micro_cny=?,
                    http_status=?, response_model=?, provider_request_id=?,
                    prompt_tokens=?, completion_tokens=?
                WHERE id=? AND status='reserved'
                """,
                (
                    "settled" if charge is not None else "unknown",
                    failure,
                    charge,
                    http_status,
                    response_model,
                    provider_request_id,
                    prompt_tokens,
                    completion_tokens,
                    reservation,
                ),
            )
            if update.rowcount != 1:
                raise DemoBudgetError("Demo model reservation could not be reconciled")

    def summary(self) -> DemoBudgetSummary:
        with self._connect("ro") as db:
            spent, reserved, requests, settled, in_flight, unknown = db.execute("""
                SELECT COALESCE(SUM(actual_micro_cny), 0),
                    COALESCE(SUM(reserved_micro_cny) FILTER (WHERE actual_micro_cny IS NULL), 0),
                    COUNT(*), COUNT(*) FILTER (WHERE status='settled'),
                    COUNT(*) FILTER (WHERE status='reserved'),
                    COUNT(*) FILTER (WHERE status='unknown')
                FROM demo_model_requests
            """).fetchone()
        return DemoBudgetSummary(
            limit_cny=_LIMIT / _MICRO_CNY,
            spent_cny=spent / _MICRO_CNY,
            reserved_cny=reserved / _MICRO_CNY,
            available_cny=(_LIMIT - spent - reserved) / _MICRO_CNY,
            requests=requests,
            settled=settled,
            in_flight=in_flight,
            unknown=unknown,
            blocked=bool(in_flight or unknown),
        )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate JSON keys")
    return result


async def _validated_request(request: httpx.Request) -> tuple[int, str]:
    if (
        request.method != "POST"
        or request.url != f"{DEMO_BASE_URL}/chat/completions"
        or request.headers.get_list("host") != ["api.deepseek.com"]
        or "sni_hostname" in request.extensions
        or "content-encoding" in request.headers
    ):
        raise DemoBudgetError(
            "Demo model requests require the official DeepSeek chat endpoint"
        )

    wire_body = await request.aread()
    try:
        body = json.loads(wire_body.decode("utf-8"), object_pairs_hook=_unique_object)
    except (ValueError, RecursionError):
        raise DemoBudgetError(
            "Demo model request must contain unambiguous JSON"
        ) from None
    if not isinstance(body, dict) or body.keys() - _REQUEST_FIELDS:
        raise DemoBudgetError("Unsupported demo model request parameters")
    max_tokens = body.get("max_tokens")
    n = body.get("n", 1)
    if (
        body.get("model") != DEMO_MODEL
        or body.get("stream", False) is not False
        or type(n) is not int
        or n != 1
        or type(max_tokens) is not int
        or not 1 <= max_tokens <= DEMO_MAX_OUTPUT_TOKENS
    ):
        raise DemoBudgetError(
            "Demo model requires one non-streaming deepseek-flash completion with max_tokens 1–4096"
        )
    tools = body.get("tools", [])
    if not isinstance(tools, list) or any(
        not isinstance(tool, dict) or tool.get("type") != "function" for tool in tools
    ):
        raise DemoBudgetError("Demo model supports function schemas only")
    return max_tokens, hashlib.sha256(wire_body).hexdigest()


def _record_response(
    ledger: _Ledger, reservation: int, response: httpx.Response, max_tokens: int
) -> None:
    try:
        body = response.json(object_pairs_hook=_unique_object)
    except (ValueError, RecursionError):
        body = None
    if not isinstance(body, dict):
        body = {}
    request_id = _safe_id(response.headers.get("x-request-id")) or _safe_id(
        body.get("id")
    )
    response_model = _safe_id(body.get("model"))
    usage = body.get("usage")
    prompt_tokens = usage.get("prompt_tokens") if isinstance(usage, dict) else None
    completion_tokens = (
        usage.get("completion_tokens") if isinstance(usage, dict) else None
    )

    failure = None
    if response.status_code != 200:
        failure = "http_status"
    elif response_model is None or response_model.lower() not in _RESPONSE_MODELS:
        failure = "unexpected_model"
    elif (
        body.get("error") is not None
        or not isinstance(usage, dict)
        or type(prompt_tokens) is not int
        or type(completion_tokens) is not int
        or not 0 <= prompt_tokens <= _MAX_INPUT_TOKENS
        or not 0 <= completion_tokens <= max_tokens
        or usage.get("total_tokens", prompt_tokens + completion_tokens)
        != prompt_tokens + completion_tokens
    ):
        failure = "unknown_usage"

    ledger.finish(
        reservation,
        failure=failure,
        http_status=response.status_code,
        response_model=response_model,
        provider_request_id=request_id,
        prompt_tokens=prompt_tokens
        if type(prompt_tokens) is int and 0 <= prompt_tokens < 2**63
        else None,
        completion_tokens=completion_tokens
        if type(completion_tokens) is int and 0 <= completion_tokens < 2**63
        else None,
    )
    if failure is not None and response.status_code == 200:
        raise DemoBudgetError(
            "Demo model usage could not be reconciled; reservation retained"
        )


class _BudgetTransport(httpx.AsyncBaseTransport):
    def __init__(self, ledger: _Ledger, transport: httpx.AsyncBaseTransport):
        self.ledger = ledger
        self.transport = transport

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        max_tokens, request_sha256 = await _validated_request(request)
        reservation = self.ledger.reserve(max_tokens, request_sha256)
        try:
            response = await self.transport.handle_async_request(request)
            try:
                await response.aread()
            finally:
                await response.aclose()
        except asyncio.CancelledError:
            self.ledger.finish(reservation, failure="interrupted")
            raise
        except Exception:
            self.ledger.finish(reservation, failure="transport_error")
            raise
        _record_response(self.ledger, reservation, response, max_tokens)
        return response

    async def aclose(self) -> None:
        await self.transport.aclose()


def create_demo_model_client(
    ledger_path: Path, *, transport: httpx.AsyncBaseTransport | None = None
) -> httpx.AsyncClient:
    ledger = _Ledger(ledger_path)
    ledger.initialize()
    if transport is None:
        # Unlike create_default_context(), this does not honor SSLKEYLOGFILE.
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls.load_verify_locations(certifi.where())
        transport = httpx.AsyncHTTPTransport(verify=tls, retries=0, trust_env=False)
    return httpx.AsyncClient(
        transport=_BudgetTransport(ledger, transport),
        trust_env=False,
        follow_redirects=False,
        timeout=60,
    )


def read_demo_budget(ledger_path: Path) -> DemoBudgetSummary:
    """Read an existing ledger without creating or changing it."""
    return _Ledger(ledger_path).summary()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Summarize the local demo model budget"
    )
    parser.add_argument("ledger_path", type=Path)
    args = parser.parse_args()
    print(json.dumps(asdict(read_demo_budget(args.ledger_path)), indent=2))
