# Task 6 Restricted MCP Tools Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete and verify the three read-only MCP investigation tools required for Task 6, including incident-scoped evidence, ATT&CK lookup, structured failures, and complete auditing.

**Architecture:** Keep business tools behind injected synchronous work callables and a shared audited async executor. Add incident-scoped alert evidence and a replaceable PostgreSQL ATT&CK adapter, then wrap FastMCP with an exact allowlist and structured error/audit boundary. Task 7 later replaces only the ATT&CK work callable with hybrid retrieval.

**Tech Stack:** Python 3.12.14, Pydantic 2.13, SQLAlchemy 2.0, PostgreSQL 17/pgvector, OpenSearch 3.8, MCP/FastMCP 1.30, pytest 9.1, Ruff 0.16, mypy 2.3.

## Global Constraints

- Expose exactly `search_security_events`, `get_alert_context`, and `lookup_attack_technique`; never expose run, incident, or trace context in tool schemas.
- Event search limit is 200, each alert window side is 900 seconds, ATT&CK lookup limit is 10, and each call deadline is 10 seconds.
- A read-only dependency operation may make one initial attempt plus at most two retries; evidence persistence is never retried.
- Validate policy before storage/search and audit every accepted or denied tool request exactly once with run ID and trace ID.
- Client-visible error codes are exactly `POLICY_DENIED`, `NOT_FOUND`, `DEPENDENCY_TIMEOUT`, and `DEPENDENCY_UNAVAILABLE`.
- Never expose tracebacks, connection strings, SQL, or raw dependency errors to MCP clients.
- `get_alert_context` may use only the current incident's alert and that alert's persisted event ID allowlist.
- `lookup_attack_technique` reads only local non-revoked, non-deprecated ATT&CK `attack-pattern` chunks and never fabricates missing knowledge.
- ATT&CK results remain `list[dict[str, str]]`; Task 7 may replace the work callable without changing the public tool or audit contract.
- Do not add Shell execution, arbitrary URL access, write-capable MCP tools, STIX download, embeddings, RRF, or citation validation.
- Continue in the current worktree as explicitly authorized for Task 6; preserve unrelated user changes.

---

### Task 1: Shared coded errors and audited tool execution

**Files:**
- Create: `services/backend/src/evidencesoc/tools/errors.py`
- Create: `services/backend/src/evidencesoc/tools/runtime.py`
- Modify: `services/backend/src/evidencesoc/tools/security_events.py`
- Modify: `services/backend/src/evidencesoc/tools/event_work.py`
- Create: `services/backend/tests/tools/test_tool_runtime.py`
- Modify: `services/backend/tests/tools/test_security_events.py`
- Modify: `services/backend/tests/tools/test_audit_sql.py`

**Interfaces:**
- Consumes: `PolicyDeniedError`, `ToolExecutionContext`, `AuditWriter`, `ToolCallRecord`.
- Produces: `ToolExecutionError`, `ToolDependencyError`, `ToolDependencyTimeout`, `ToolNotFoundError`, `run_audited_tool(...)`, and `validate_evidence_items(...)`.

- [ ] **Step 1: Write failing runtime tests**

Create tests that prove validation runs before work, unexpected work failures become coded dependency failures, and success/failure writes exactly one audit record:

```python
@pytest.mark.asyncio
async def test_runtime_validates_before_work_and_audits_denial() -> None:
    calls: list[str] = []
    audit = AuditSpy()

    def validate() -> None:
        raise PolicyDeniedError("denied before storage")

    with pytest.raises(PolicyDeniedError):
        await run_audited_tool(
            context=CONTEXT,
            audit=audit,
            tool_name="search_security_events",
            arguments={"limit": 201},
            validate=validate,
            work=lambda: calls.append("work"),
            validate_result=lambda _result: 0,
        )

    assert calls == []
    assert len(audit.records) == 1
    assert audit.records[0].error_code == "POLICY_DENIED"
    assert audit.records[0].result["trace_id"] == CONTEXT.trace_id


@pytest.mark.asyncio
async def test_runtime_wraps_unexpected_dependency_failure() -> None:
    audit = AuditSpy()

    def fail() -> list[EvidenceItem]:
        raise RuntimeError("secret database detail")

    with pytest.raises(ToolDependencyError, match="dependency unavailable"):
        await run_audited_tool(
            context=CONTEXT,
            audit=audit,
            tool_name="search_security_events",
            arguments={},
            validate=lambda: None,
            work=fail,
            validate_result=lambda result: len(result),
        )

    assert audit.records[0].error_code == "DEPENDENCY_UNAVAILABLE"
    assert "secret database detail" not in audit.records[0].result["reason"]
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```powershell
cd services/backend
.\.venv\Scripts\python.exe -m pytest tests/tools/test_tool_runtime.py -q
```

Expected: collection fails because `evidencesoc.tools.runtime` and `evidencesoc.tools.errors` do not exist.

- [ ] **Step 3: Implement the common error and runtime contracts**

Add the exact coded hierarchy:

```python
class ToolExecutionError(RuntimeError):
    code = "DEPENDENCY_UNAVAILABLE"
    public_message = "dependency unavailable"


class ToolDependencyError(ToolExecutionError):
    pass


class ToolDependencyTimeout(ToolExecutionError):
    code = "DEPENDENCY_TIMEOUT"
    public_message = "dependency timed out"


class ToolNotFoundError(ToolExecutionError):
    code = "NOT_FOUND"
    public_message = "resource not found"
```

Implement `run_audited_tool` with this signature and behavior:

```python
T = TypeVar("T")


async def run_audited_tool(
    *,
    context: ToolExecutionContext,
    audit: AuditWriter,
    tool_name: str,
    arguments: dict[str, Any],
    validate: Callable[[], None],
    work: Callable[[], T],
    validate_result: Callable[[T], int],
    deadline_seconds: float = 10.0,
) -> T:
    started_at = datetime.now(UTC)
```

It must call `validate()` synchronously, then run `asyncio.to_thread(work)` under `asyncio.timeout(deadline_seconds)`, validate the returned result, and write one success or failure `ToolCallRecord`. A deadline expiry becomes `ToolDependencyTimeout("dependency timed out")`. It catches `PolicyDeniedError` and `ToolExecutionError` without changing their code; any other work/result exception is wrapped as `ToolDependencyError("dependency unavailable")`. Audit results contain `trace_id`, `result_count` on success, and a sanitized `reason` on failure. When result validation fails after a list was returned, preserve `result_count=len(value)` in the failure record so the existing over-limit and wrong-item audit contract remains intact. The injectable timeout is internal only; every production caller uses the 10-second default.

Add a deadline test with a short injected timeout and a `threading.Event`-controlled worker. Assert `DEPENDENCY_TIMEOUT`, exactly one audit record, and release/join the worker in `finally` so no executor thread leaks from the test.

Add:

```python
def validate_evidence_items(value: object, *, limit: int) -> int:
    if not isinstance(value, list):
        raise ToolDependencyError("dependency returned a non-list result")
    if len(value) > limit:
        raise ToolDependencyError("dependency returned too many results")
    if any(not isinstance(item, EvidenceItem) for item in value):
        raise ToolDependencyError("dependency returned an invalid evidence item")
    return len(value)
```

Refactor `SecurityEventTools.search_security_events` to delegate to `run_audited_tool`, retain its public signature, and re-export `ToolDependencyError` from `security_events.py` for compatibility. Update `event_work.py` to import all coded errors from `tools.errors`.

`run_audited_tool.arguments` is the JSON-safe audit representation, not necessarily the keyword arguments passed to `work`. For event search, keep aware `datetime` objects in the work closure but pass ISO-8601 strings in the audit dictionary:

```python
audit_arguments = {
    "time_from": time_from.isoformat(),
    "time_to": time_to.isoformat(),
    "filters": dict(filters),
    "limit": limit,
}
```

Add one `SqlAuditWriter` regression using a real temporary SQLite `tool_calls` table and a successful empty event search. Query the stored row and assert `arguments.time_from` and `arguments.time_to` are strings; the commit itself must not raise a JSON serialization error.

- [ ] **Step 4: Run runtime and existing event-tool tests and verify GREEN**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/tools/test_tool_runtime.py tests/tools/test_security_events.py tests/tools/test_audit_sql.py tests/evidence/test_service.py -q
```

Expected: all selected tests pass and each denial/failure test observes exactly one audit record.

- [ ] **Step 5: Commit Task 1**

```powershell
git add services/backend/src/evidencesoc/tools/errors.py services/backend/src/evidencesoc/tools/runtime.py services/backend/src/evidencesoc/tools/security_events.py services/backend/src/evidencesoc/tools/event_work.py services/backend/tests/tools/test_tool_runtime.py services/backend/tests/tools/test_security_events.py services/backend/tests/tools/test_audit_sql.py
git commit -m "refactor(backend): centralize audited tool execution"
```

### Task 2: Incident-scoped alert context evidence

**Files:**
- Create: `services/backend/src/evidencesoc/tools/alert_context.py`
- Create: `services/backend/src/evidencesoc/tools/alert_work.py`
- Create: `services/backend/tests/tools/test_alert_context.py`
- Create: `services/backend/tests/tools/test_alert_work.py`

**Interfaces:**
- Consumes: `run_audited_tool`, `validate_alert_context`, `EvidenceService`, `AlertTable`, `IncidentTable`, `SecurityEventTable`.
- Produces: `AlertContextTools.get_alert_context(...)`, `AlertContextRepository.list_event_ids(...)`, `AlertContextWork`, and `build_alert_context_work(...)`.

- [ ] **Step 1: Write failing alert-tool boundary tests**

Cover blank/negative/901-second arguments before work, valid delegation, a 200-result cap, evidence type validation, coded dependency errors, and one audit row:

```python
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("alert_id", "before", "after"),
    [("", 900, 900), ("AL-1", -1, 0), ("AL-1", 901, 0), ("AL-1", 0, -1), ("AL-1", 0, 901)],
)
async def test_alert_policy_denial_precedes_work(
    alert_id: str, before: int, after: int
) -> None:
    work = WorkSpy([])
    audit = AuditSpy()
    tool = AlertContextTools(context=CONTEXT, work=work, audit=audit)

    with pytest.raises(PolicyDeniedError):
        await tool.get_alert_context(alert_id, before, after)

    assert work.calls == []
    assert [record.error_code for record in audit.records] == ["POLICY_DENIED"]


@pytest.mark.asyncio
async def test_alert_context_delegates_incident_scope_and_audits() -> None:
    work = WorkSpy([])
    audit = AuditSpy()
    tool = AlertContextTools(context=CONTEXT, work=work, audit=audit)

    assert await tool.get_alert_context("AL-1", 300, 600) == []
    assert work.calls == [{
        "alert_id": "AL-1",
        "before_seconds": 300,
        "after_seconds": 600,
        "incident_id": CONTEXT.incident_id,
    }]
    assert audit.records[0].result == {
        "trace_id": CONTEXT.trace_id,
        "result_count": 0,
    }
```

- [ ] **Step 2: Run alert boundary tests and verify RED**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/tools/test_alert_context.py -q
```

Expected: import fails because `evidencesoc.tools.alert_context` does not exist.

- [ ] **Step 3: Implement `AlertContextTools`**

Implement:

```python
MAX_ALERT_CONTEXT_RESULTS = 200


class AlertContextTools:
    def __init__(
        self,
        *,
        context: ToolExecutionContext,
        work: Callable[..., list[EvidenceItem]],
        audit: AuditWriter,
    ) -> None:
        self._context = context
        self._work = work
        self._audit = audit

    async def get_alert_context(
        self,
        alert_id: str,
        before_seconds: int = 900,
        after_seconds: int = 900,
    ) -> list[EvidenceItem]:
        arguments = {
            "alert_id": alert_id,
            "before_seconds": before_seconds,
            "after_seconds": after_seconds,
        }
        result = await run_audited_tool(
            context=self._context,
            audit=self._audit,
            tool_name="get_alert_context",
            arguments=arguments,
            validate=lambda: validate_alert_context(
                alert_id, before_seconds, after_seconds
            ),
            work=lambda: self._work(
                **arguments,
                incident_id=self._context.incident_id,
            ),
            validate_result=lambda value: validate_evidence_items(
                value, limit=MAX_ALERT_CONTEXT_RESULTS
            ),
        )
        return result
```

- [ ] **Step 4: Run alert boundary tests and verify GREEN**

Run the Step 2 command. Expected: all alert boundary tests pass.

- [ ] **Step 5: Write failing alert repository/work tests**

Use a temporary SQLite database with raw `alerts`, `incidents`, and `security_events` tables to prove `(incident_id, alert_id)` binding, event-ID allowlisting, inclusive time filtering, deterministic ordering, and the 200-row cap. Add work tests using fakes to prove missing/mismatched alerts map to `NOT_FOUND`, transient read failures make at most three attempts, deadlines stop before evidence persistence, and evidence persistence is called once without retry.

The primary behavior assertion is:

```python
assert repository.list_event_ids(
    incident_id="IN-1",
    alert_id="AL-1",
    before_seconds=300,
    after_seconds=300,
    limit=200,
) == ["EVT-in-window-1", "EVT-in-window-2"]
```

Add separate assertions that an event inside the time window but absent from `Alert.event_ids` is excluded, an allowlisted event outside the window is excluded, and the same alert queried through `IN-other` raises `ToolNotFoundError`.

- [ ] **Step 6: Run alert work tests and verify RED**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/tools/test_alert_work.py -q
```

Expected: import fails because `evidencesoc.tools.alert_work` does not exist.

- [ ] **Step 7: Implement alert repository, work, and production builder**

Implement `AlertContextRepository.list_event_ids` with two bound SQLAlchemy selects:

```python
alert = session.execute(
    select(AlertTable.created_at, AlertTable.event_ids)
    .join(IncidentTable, IncidentTable.alert_id == AlertTable.alert_id)
    .where(
        IncidentTable.incident_id == incident_id,
        AlertTable.alert_id == alert_id,
    )
).one_or_none()
```

Raise `ToolNotFoundError("alert context not found")` when this returns `None`. Otherwise select only `SecurityEventTable.event_id` where the ID is in the alert allowlist and `observed_at` is between the inclusive UTC bounds, order by `(observed_at, event_id)`, and apply `.limit(limit)`.

Implement `AlertContextWork` with a 10-second monotonic deadline, at most three attempts for `OperationalError` during the read-only repository call, a deadline check before evidence creation, and one non-retried `EvidenceService.create_for_events` call with this query metadata:

```python
{
    "alert_id": alert_id,
    "before_seconds": before_seconds,
    "after_seconds": after_seconds,
    "limit": 200,
}
```

Map evidence source/incident absence to `ToolNotFoundError`, OpenSearch timeout to `ToolDependencyTimeout`, and integrity/SQL/OpenSearch transport failure to `ToolDependencyError`.

For production PostgreSQL reads, set a transaction-local statement timeout from the remaining budget with parameterized `SELECT set_config('statement_timeout', :milliseconds, true)` before the alert/event query. `build_alert_context_work` creates an OpenSearch client with a 10-second default request timeout and hidden retries disabled, applies the remaining PostgreSQL statement budget before evidence verification/persistence, and creates sessions/evidence services inside the worker thread, matching `build_event_search_work`. The shared runtime timeout remains the outer client-visible deadline if connection acquisition or a multi-event evidence operation outlives its dependency timeout. Unit tests use fake clocks and timeout-raising dependencies; they must prove a timed-out read never reaches evidence persistence.

- [ ] **Step 8: Run all alert tests and verify GREEN**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/tools/test_alert_context.py tests/tools/test_alert_work.py -q
```

Expected: all alert tests pass.

- [ ] **Step 9: Commit Task 2**

```powershell
git add services/backend/src/evidencesoc/tools/alert_context.py services/backend/src/evidencesoc/tools/alert_work.py services/backend/tests/tools/test_alert_context.py services/backend/tests/tools/test_alert_work.py
git commit -m "feat(backend): add incident-scoped alert context tool"
```

### Task 3: Replaceable local ATT&CK lookup

**Files:**
- Modify: `services/backend/src/evidencesoc/tools/attack.py`
- Create: `services/backend/src/evidencesoc/tools/attack_work.py`
- Modify: `services/backend/tests/tools/test_attack.py`
- Create: `services/backend/tests/tools/test_attack_work.py`
- Create: `services/backend/tests/integration/test_attack_lookup.py`

**Interfaces:**
- Consumes: `run_audited_tool`, `validate_attack_lookup`, `KnowledgeChunkTable`, SQLAlchemy sessions.
- Produces: `AttackTools.lookup_attack_technique(...)`, `AttackKnowledgeRepository.lookup(...)`, `AttackLookupWork`, and `build_attack_lookup_work(...)`.

- [ ] **Step 1: Write failing `AttackTools` tests**

Cover validation before work, successful empty/nonempty results, stable string-only result shape, result caps, malformed dependency results, timeout/unavailable propagation, and exact audit counts:

```python
ATTACK_RESULT = {
    "knowledge_chunk_id": "KC-T1190",
    "technique_id": "T1190",
    "title": "Exploit Public-Facing Application",
    "summary": "Adversaries may exploit an internet-facing application.",
    "source_uri": "https://attack.mitre.org/techniques/T1190/",
    "version": "19.2",
}


@pytest.mark.asyncio
async def test_attack_lookup_returns_stable_records_and_audits() -> None:
    work = WorkSpy([ATTACK_RESULT])
    audit = AuditSpy()
    tool = AttackTools(context=CONTEXT, work=work, audit=audit)

    assert await tool.lookup_attack_technique("T1190", limit=10) == [ATTACK_RESULT]
    assert work.calls == [{"query": "T1190", "limit": 10}]
    assert audit.records[0].result == {
        "trace_id": CONTEXT.trace_id,
        "result_count": 1,
    }


@pytest.mark.asyncio
async def test_unknown_technique_returns_empty_without_fabrication() -> None:
    tool = AttackTools(context=CONTEXT, work=WorkSpy([]), audit=AuditSpy())
    assert await tool.lookup_attack_technique("T9999", 10) == []
```

- [ ] **Step 2: Run attack-tool tests and verify RED**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/tools/test_attack.py -q
```

Expected: imports fail because the current `attack.py` is empty.

- [ ] **Step 3: Implement `AttackTools` and result validation**

Define:

```python
ATTACK_RESULT_FIELDS = frozenset({
    "knowledge_chunk_id",
    "technique_id",
    "title",
    "summary",
    "source_uri",
    "version",
})


def validate_attack_results(value: object, *, limit: int) -> int:
    if not isinstance(value, list) or len(value) > limit:
        raise ToolDependencyError("attack lookup returned invalid results")
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != ATTACK_RESULT_FIELDS
            or any(not isinstance(field, str) or not field.strip() for field in item.values())
        ):
            raise ToolDependencyError("attack lookup returned invalid results")
    return len(value)
```

Implement `AttackTools.lookup_attack_technique(query, limit=10)` through `run_audited_tool`, validating with `validate_attack_lookup`, calling injected work with only `query` and `limit`, and validating through `validate_attack_results`.

- [ ] **Step 4: Run attack-tool tests and verify GREEN**

Run the Step 2 command. Expected: all `AttackTools` tests pass.

- [ ] **Step 5: Write failing SQL adapter and retry tests**

Tests must prove:

- SQL is parameterized and `%`, `_`, and `\\` are escaped for `ILIKE ... ESCAPE '\\'`;
- only `metadata.object_type == "attack-pattern"` with false/missing `revoked` and `deprecated` is eligible;
- exact case-insensitive Technique ID ranks first, then title/content matches, then `knowledge_chunk_id`;
- result mapping uses `source` as `source_uri`, `content` as `summary`, and required metadata strings;
- a missing/unknown row returns `[]`;
- a query matching `^T\d{4}(?:\.\d{3})?$` is treated only as a case-insensitive exact Technique ID lookup, so an unknown ID cannot match another chunk's content;
- `OperationalError` receives at most three read attempts under one 10-second deadline;
- invalid row metadata becomes `DEPENDENCY_UNAVAILABLE`.

Compile the statement with `postgresql.dialect()` and assert the user query is present only in bound parameters, never the SQL string.

Also create a live PostgreSQL integration test that inserts two uniquely prefixed `knowledge_chunks` rows with real JSONB metadata, invokes `AttackKnowledgeRepository.lookup`, and deletes both rows in `finally`. Assert exact-ID ranking, revoked/deprecated exclusion, wildcard escaping, and `T9999 -> []`. This test runs only after Task 8 starts PostgreSQL and applies migrations; it is not part of the dependency-free RED/GREEN loop below.

- [ ] **Step 6: Run ATT&CK work tests and verify RED**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/tools/test_attack_work.py -q
```

Expected: import fails because `evidencesoc.tools.attack_work` does not exist.

- [ ] **Step 7: Implement local knowledge query and replaceable work adapter**

Implement `_escape_like`:

```python
def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
```

Classify a stripped query with `re.fullmatch(r"T\d{4}(?:\.\d{3})?", query, re.IGNORECASE)`. For that form, build an exact case-insensitive `metadata.technique_id` predicate only; do not fall back to title/content matching. For ordinary text, build one SQLAlchemy select over `KnowledgeChunkTable` with JSONB string/boolean accessors, bound `ILIKE` clauses using `escape="\\"`, title/content ranking through `case`, and `.limit(limit)`. Both branches require `metadata.object_type == "attack-pattern"`, accept only false/missing `revoked` and `deprecated`, order deterministically by `knowledge_chunk_id`, map `source` plus metadata keys `technique_id`, `title`, and `version` to the six-field contract, and reject missing/non-string fields with `ToolDependencyError`.

`AttackKnowledgeRepository.lookup` applies a transaction-local PostgreSQL statement timeout from the remaining budget via parameterized `set_config`. `AttackLookupWork` owns a 10-second monotonic deadline and retries only `OperationalError` at most twice after the initial attempt. `build_attack_lookup_work(session_factory=...)` returns this callable without querying the database during construction; the shared runtime timeout is the outer client-visible deadline if connection acquisition blocks.

- [ ] **Step 8: Run all ATT&CK tests and verify GREEN**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/tools/test_attack.py tests/tools/test_attack_work.py tests/tools/test_policy.py -q
```

Expected: all selected tests pass; no ATT&CK/STIX network access occurs.

- [ ] **Step 9: Commit Task 3**

```powershell
git add services/backend/src/evidencesoc/tools/attack.py services/backend/src/evidencesoc/tools/attack_work.py services/backend/tests/tools/test_attack.py services/backend/tests/tools/test_attack_work.py services/backend/tests/integration/test_attack_lookup.py
git commit -m "feat(backend): add replaceable ATT&CK lookup tool"
```

### Task 4: Restricted FastMCP boundary and exact three-tool server

**Files:**
- Create: `services/backend/src/evidencesoc/mcp_server/restricted.py`
- Modify: `services/backend/src/evidencesoc/mcp_server/main.py`
- Modify: `services/backend/tests/tools/test_mcp_server.py`

**Interfaces:**
- Consumes: three business tool objects, `RunContext`, `AuditWriter`, `ALLOWED_TOOLS`, FastMCP `CallToolResult`.
- Produces: `RestrictedFastMCP`, `structured_tool_error(...)`, `create_server(...)`, and a production `build_server(...)` exposing exactly three tools.

- [ ] **Step 1: Replace the one-tool server test with failing three-tool/schema tests**

Construct all three tool objects with work spies and assert:

```python
tools = await server.list_tools()
assert {tool.name for tool in tools} == {
    "search_security_events",
    "get_alert_context",
    "lookup_attack_technique",
}
assert len(tools) == 3
for tool in tools:
    assert not ({"run_id", "incident_id", "trace_id"} & set(tool.inputSchema["properties"]))
```

Also call each valid tool directly and assert it delegates to the correct work spy with context hidden.

- [ ] **Step 2: Add failing structured boundary denial tests**

Cover `run_shell`, missing required arguments, wrong types, extra arguments, business `POLICY_DENIED`, `NOT_FOUND`, `DEPENDENCY_TIMEOUT`, and `DEPENDENCY_UNAVAILABLE`. For a boundary denial assert:

```python
result = await server.call_tool("run_shell", {})
assert isinstance(result, CallToolResult)
assert result.isError is True
assert result.structuredContent == {
    "error": {
        "code": "POLICY_DENIED",
        "message": "request denied",
        "trace_id": "TRACE-test",
    }
}
assert json.loads(result.content[0].text) == result.structuredContent
assert len(boundary_audit.records) == 1
assert boundary_audit.records[0].tool_name == "run_shell"
```

For business failures assert the business audit contains exactly one record and the boundary audit does not add a duplicate.

- [ ] **Step 3: Run MCP server tests and verify RED**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/tools/test_mcp_server.py -q
```

Expected: failures show only one registered tool and default FastMCP plaintext errors.

- [ ] **Step 4: Implement `RestrictedFastMCP`**

Define exact argument contracts:

```python
TOOL_ARGUMENTS = {
    "search_security_events": (
        frozenset({"time_from", "time_to", "filters"}),
        frozenset({"limit"}),
    ),
    "get_alert_context": (
        frozenset({"alert_id"}),
        frozenset({"before_seconds", "after_seconds"}),
    ),
    "lookup_attack_technique": (
        frozenset({"query"}),
        frozenset({"limit"}),
    ),
}
```

`RestrictedFastMCP.call_tool` must reject an unknown name, missing required key, or extra key before `super().call_tool`. It records one boundary `ToolCallRecord` with `POLICY_DENIED` and returns a `CallToolResult` containing identical JSON in `structuredContent` and text content.

Use a per-call `ContextVar[bool]` initialized to `False`; each registered wrapper sets it to `True` immediately before invoking its business tool. This makes concurrent calls safe and lets the boundary distinguish FastMCP/Pydantic rejection before business invocation from an exception after the business audit. Always reset the token in `finally`.

For delegated exceptions, walk `__cause__` until an object with one of the four allowed `.code` values is found. Coded business exceptions were already audited, so only format the client response. Pydantic/FastMCP argument errors with the invocation marker still `False` are boundary-audited as `POLICY_DENIED`. An unclassified exception returns `DEPENDENCY_UNAVAILABLE` with the public message `dependency unavailable`; add a boundary audit only when the marker proves business code was not invoked. This preserves exactly one audit record even if FastMCP result conversion fails after a successful business audit. Because MCP 1.30's public `FastMCP.call_tool` annotation omits the `CallToolResult` type already accepted by its low-level handler, annotate the override return as `Any` and cover both direct and real-stdio behavior in tests.

- [ ] **Step 5: Register all three tools and production adapters**

Change `create_server` to accept:

```python
def create_server(
    *,
    context: RunContext,
    boundary_audit: AuditWriter,
    event_tools: SecurityEventTools,
    alert_tools: AlertContextTools,
    attack_tools: AttackTools,
) -> RestrictedFastMCP:
```

Register the three public functions with exactly the signatures in the approved spec. Change `build_server` to create one `SqlAuditWriter`, then create `SecurityEventTools`, `AlertContextTools`, and `AttackTools` using `build_event_search_work`, `build_alert_context_work`, and `build_attack_lookup_work`. Validate AgentRun ownership before constructing the server.

- [ ] **Step 6: Run MCP server and tool tests and verify GREEN**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/tools/test_mcp_server.py tests/tools/test_security_events.py tests/tools/test_alert_context.py tests/tools/test_attack.py -q
```

Expected: all tests pass, exactly three tools are discoverable, and every error assertion parses machine-readable JSON.

- [ ] **Step 7: Commit Task 4**

```powershell
git add services/backend/src/evidencesoc/mcp_server/restricted.py services/backend/src/evidencesoc/mcp_server/main.py services/backend/tests/tools/test_mcp_server.py
git commit -m "feat(backend): enforce restricted MCP tool boundary"
```

### Task 5: Real stdio three-tool discovery and denial audit

**Files:**
- Modify: `services/backend/tests/tools/test_mcp_client.py`

**Interfaces:**
- Consumes: unchanged `open_stdio_session(...)` and the production MCP module entry point.
- Produces: real child-process proof of three-tool discovery, structured errors, and persisted boundary audit.

- [ ] **Step 1: Extend the temporary SQLite fixture**

Create both `agent_runs` and `tool_calls` with raw SQLite DDL. The `tool_calls` table must contain:

```sql
tool_call_id VARCHAR(64) PRIMARY KEY,
run_id VARCHAR(64) NOT NULL,
tool_name VARCHAR(128) NOT NULL,
arguments JSON NOT NULL,
result JSON,
started_at DATETIME NOT NULL,
finished_at DATETIME,
success BOOLEAN NOT NULL,
error_code VARCHAR(64)
```

Keep the existing AgentRun row and do not create alert/knowledge tables; server construction and discovery must stay lazy.

- [ ] **Step 2: Change discovery expectations and add a failing real denial test**

Assert two calls to `session.list_tools()` both return exactly the three required names and schemas. Then call:

```python
denial = await session.call_tool("run_shell", {})
assert denial.isError is True
assert denial.structuredContent["error"]["code"] == "POLICY_DENIED"
assert denial.structuredContent["error"]["trace_id"] == "TRACE-42"
```

After closing the child, query SQLite and assert exactly one `tool_calls` row exists for `run_shell`, `success == 0`, and `error_code == "POLICY_DENIED"`.

- [ ] **Step 3: Run the real stdio integration test**

Run outside the Windows sandbox because MCP stdio needs named-pipe permission:

```powershell
cd services/backend
.\.venv\Scripts\python.exe -m pytest tests/tools/test_mcp_client.py -q
```

Expected after Task 4: all assertions pass. A failure here is an integration defect—most likely child-process serialization or SQLite audit compatibility—not a new unit-level RED phase; preserve the failure output before making the Step 4 correction.

- [ ] **Step 4: Make only fixture/serialization compatibility corrections**

If SQLAlchemy's PostgreSQL JSON bind processor needs JSON strings under SQLite, register adapters in the fixture or deserialize with `json.loads`; do not weaken the production audit schema or skip the persisted-row assertion. Do not add alert/knowledge queries during startup.

- [ ] **Step 5: Run Task 6 focused tests and verify GREEN**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/tools tests/evidence/test_service.py tests/persistence/test_event_search.py -q
```

Expected: all focused Task 6 tests pass.

- [ ] **Step 6: Commit Task 5**

```powershell
git add services/backend/tests/tools/test_mcp_client.py
git commit -m "test(backend): verify restricted MCP stdio boundary"
```

### Task 6: Make backend dotenv loading working-directory independent

**Files:**
- Modify: `services/backend/src/evidencesoc/config.py`
- Create: `services/backend/tests/test_config.py`

**Interfaces:**
- Consumes: repository-root `.env`, Pydantic settings precedence.
- Produces: `REPOSITORY_ROOT`, absolute default dotenv path, unchanged `Settings(_env_file=None)` behavior.

- [ ] **Step 1: Write a failing default-path test**

```python
def test_default_dotenv_path_is_absolute_repository_root() -> None:
    env_file = Path(Settings.model_config["env_file"])
    assert env_file.is_absolute()
    assert env_file == REPOSITORY_ROOT / ".env"


def test_settings_result_does_not_depend_on_working_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    env_file = tmp_path / "project.env"
    env_file.write_text(
        "OPENSEARCH_URL=http://127.0.0.1:19201\n",
        encoding="utf-8",
    )
    first_cwd = tmp_path / "first"
    second_cwd = tmp_path / "second"
    first_cwd.mkdir()
    second_cwd.mkdir()
    monkeypatch.delenv("OPENSEARCH_URL", raising=False)
    monkeypatch.setitem(Settings.model_config, "env_file", env_file)

    monkeypatch.chdir(first_cwd)
    first = Settings().opensearch_url
    monkeypatch.chdir(second_cwd)
    second = Settings().opensearch_url

    assert first == second == "http://127.0.0.1:19201"
```

Add deterministic temporary-dotenv tests proving explicit environment values override dotenv and `_env_file=None` ignores dotenv. The first assertion pins the real default to `REPOSITORY_ROOT / ".env"`; the two-directory test proves an absolute dotenv path behaves identically from different working directories without relying on the developer's current root `.env` contents.

- [ ] **Step 2: Run configuration tests and verify RED**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_config.py -q
```

Expected: the default path assertion fails because the current value is relative `.env`.

- [ ] **Step 3: Implement the absolute repository-root dotenv path**

```python
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = BACKEND_ROOT.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=REPOSITORY_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )
```

Do not change field defaults or environment variable names.

- [ ] **Step 4: Run configuration tests and verify GREEN**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_config.py -q
```

Expected: all configuration tests pass from `services/backend`; the live dependency test is deferred until Task 8 starts PostgreSQL and OpenSearch, where it must pass without manually setting `OPENSEARCH_URL`.

- [ ] **Step 5: Commit Task 6**

```powershell
git add services/backend/src/evidencesoc/config.py services/backend/tests/test_config.py
git commit -m "fix(backend): make settings loading cwd-independent"
```

### Task 7: Clear the full backend Ruff baseline

**Files:**
- Modify: `services/backend/src/evidencesoc/ingestion/normalize.py`
- Modify: `services/backend/migrations/env.py`
- Modify: `services/backend/tests/evidence/test_service.py`
- Modify: `services/backend/tests/ingestion/test_normalize.py`
- Modify: `services/backend/tests/ingestion/test_service.py`
- Modify: `services/backend/tests/integration/test_ingestion_pipeline.py`
- Modify: `services/backend/tests/persistence/test_event_repository.py`
- Modify: `services/backend/tests/persistence/test_event_search.py`
- Modify: `services/backend/tests/test_health.py`
- Modify: `services/backend/tests/tools/test_audit_sql.py`
- Modify: `services/backend/tests/tools/test_policy.py`
- Modify: `services/backend/tests/tools/test_security_events.py`

**Interfaces:**
- Consumes: Python 3.12 native trailing-`Z` ISO parsing and Ruff import grouping.
- Produces: a zero-error full backend Ruff check with unchanged runtime behavior.

- [ ] **Step 1: Capture the failing Ruff baseline**

Run:

```powershell
.\.venv\Scripts\python.exe -m ruff check .
```

Expected: the known import-order findings plus `FURB162` fail. Record the exact count because Task 1-5 may already have changed import blocks.

- [ ] **Step 2: Add a trailing-`Z` normalization regression test**

Add to `tests/ingestion/test_normalize.py`:

```python
def test_normalize_accepts_utc_z_suffix() -> None:
    raw = valid_raw()
    raw["observed_at"] = "2026-09-21T12:00:00Z"

    event = normalize(raw)

    assert event.observed_at == datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
```

- [ ] **Step 3: Remove the redundant timezone replacement**

Change:

```python
parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
```

to:

```python
parsed = datetime.fromisoformat(value.strip())
```

- [ ] **Step 4: Apply only Ruff import sorting**

Run:

```powershell
.\.venv\Scripts\python.exe -m ruff check . --select I001 --fix
```

Review the diff and confirm it only adds blank lines or reorders existing imports. Do not run broad formatting or unsafe fixes.

- [ ] **Step 5: Verify normalize behavior and full Ruff GREEN**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/ingestion/test_normalize.py -q
.\.venv\Scripts\python.exe -m ruff check .
```

Expected: normalization tests pass and Ruff reports `All checks passed!`.

- [ ] **Step 6: Commit Task 7**

```powershell
git add services/backend/src/evidencesoc/ingestion/normalize.py services/backend/migrations/env.py services/backend/tests/evidence/test_service.py services/backend/tests/ingestion/test_normalize.py services/backend/tests/ingestion/test_service.py services/backend/tests/integration/test_ingestion_pipeline.py services/backend/tests/persistence/test_event_repository.py services/backend/tests/persistence/test_event_search.py services/backend/tests/test_health.py services/backend/tests/tools/test_audit_sql.py services/backend/tests/tools/test_policy.py services/backend/tests/tools/test_security_events.py
git commit -m "chore(backend): clear Ruff quality baseline"
```

### Task 8: Full acceptance, independent review, and roadmap status

**Files:**
- Modify after all gates pass: `docs/EvidenceSOC-project-preparation.md`

**Interfaces:**
- Consumes: all Task 1-7 commits and live PostgreSQL/OpenSearch services.
- Produces: fresh acceptance evidence and checked Task 6 roadmap boxes.

- [ ] **Step 1: Start and verify required dependencies**

Run from the repository root. First record whether each service is already running, then start only what acceptance needs:

```powershell
docker compose ps --format json
docker compose up -d --wait postgres opensearch
docker compose ps
cd services/backend
.\.venv\Scripts\python.exe -m alembic upgrade head
cd ..\..
```

Expected: PostgreSQL and OpenSearch are both healthy and the database is at the migration head. Save the pre-run `ps` output so Step 7 can stop only services that were not already running.

- [ ] **Step 2: Run focused and full backend tests**

Run outside the Windows sandbox:

```powershell
cd services/backend
.\.venv\Scripts\python.exe -m pytest tests/tools -q
.\.venv\Scripts\python.exe -m pytest tests/integration/test_attack_lookup.py tests/integration/test_dependencies.py -q
.\.venv\Scripts\python.exe -m pytest -q
```

Expected: zero failures; the live ATT&CK adapter query executes against PostgreSQL JSONB, dependency tests use the root dotenv configuration without an `OPENSEARCH_URL` override, and the full count is recorded in the completion report.

- [ ] **Step 3: Run full static and patch checks**

Run:

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy src
cd ..\..
git diff --check e60393b..HEAD
git diff --check
git status --short
```

Expected: Ruff, mypy, both committed-range and working-tree diff checks exit zero; status contains only intended Task 6/quality files.

- [ ] **Step 4: Request independent code review**

Provide the reviewer with the approved design, this plan, the full diff since `e60393b`, and the fresh test/lint evidence. Require plan-alignment and code-quality verdicts. Resolve every Critical or Important issue, rerun Steps 2-3, and, when review changes were needed, commit only those reviewed files:

```powershell
git status --short
git add -u -- services/backend docs
git commit -m "fix(backend): resolve Task 6 review findings"
```

Run the scoped `git add -u` only after the status output confirms every tracked change under those directories is a review fix; if any unrelated user change appears, stage the review files individually instead. If the reviewer reports no Critical or Important issues, do not create an empty commit.

- [ ] **Step 5: Mark Task 6 complete only after all gates pass**

In `docs/EvidenceSOC-project-preparation.md`, change Task 6 Steps 1-5 from `- [ ]` to `- [x]`. Do not change Task 7 or later tasks.

- [ ] **Step 6: Commit final acceptance status**

```powershell
git add docs/EvidenceSOC-project-preparation.md
git commit -m "docs: mark restricted MCP tools complete"
```

- [ ] **Step 7: Restore dependency process state and report evidence**

Compare the current Compose state with the Step 1 snapshot. For each service that this execution started but that was previously stopped, run the explicit service-scoped command (for example, `docker compose stop postgres` or `docker compose stop opensearch`); leave pre-existing services running. Finish with `git diff --check e60393b..HEAD` and `git status --short`, which must show no unintended working-tree changes. Report commit hashes, exact test count, Ruff/mypy/diff results, and any nonblocking warning. Do not claim Task 7 ATT&CK ingestion or hybrid retrieval is complete.
