# Task 6 completion design

## Goal

Complete the read-only MCP investigation tools required by `EvidenceSOC-project-preparation.md` so Task 6 can be accepted independently of Task 7, while preserving a clean upgrade path to the full MITRE ATT&CK v19.2 hybrid retriever.

## Public tools

The MCP server exposes exactly these asynchronous tools and no others:

```python
async def search_security_events(
    time_from: datetime,
    time_to: datetime,
    filters: dict[str, str],
    limit: int = 100,
) -> list[EvidenceItem]: ...

async def get_alert_context(
    alert_id: str,
    before_seconds: int = 900,
    after_seconds: int = 900,
) -> list[EvidenceItem]: ...

async def lookup_attack_technique(
    query: str,
    limit: int = 10,
) -> list[dict[str, str]]: ...
```

Run, incident, and trace context remains private server state and never appears in a public tool schema.

## Alert context

`get_alert_context` validates arguments before touching a dependency. It resolves an alert only when the alert is bound through `incidents` to the current AgentRun incident. A missing or differently bound alert is reported as `NOT_FOUND` without revealing whether another incident owns it.

The result set is restricted to the alert's persisted `event_ids` allowlist. Events are filtered to the inclusive alert-time context window derived from `Alert.created_at - before_seconds` through `Alert.created_at + after_seconds`, ordered deterministically, and capped at 200. Each selected event passes through `EvidenceService`, which verifies PostgreSQL/OpenSearch consistency and persists an `EvidenceItem` for the current incident.

This design intentionally rejects a global time-window search: it could attach unrelated events from another investigation to the current incident.

## ATT&CK lookup and Task 7 extension point

Task 6 adds an `AttackTools` boundary with an injected synchronous lookup work callable. The production Task 6 adapter performs bounded, parameterized, read-only keyword and Technique ID queries against the existing PostgreSQL `knowledge_chunks` table.

Only rows whose metadata identifies a non-revoked, non-deprecated ATT&CK `attack-pattern` are eligible. Exact Technique ID matches sort before title/content keyword matches, followed by deterministic IDs. User wildcard characters are escaped and never interpolated into SQL.

Every result contains only string values with this stable shape:

```python
{
    "knowledge_chunk_id": "KC-...",
    "technique_id": "T1190",
    "title": "Exploit Public-Facing Application",
    "summary": "...",
    "source_uri": "https://attack.mitre.org/techniques/T1190/",
    "version": "19.2",
}
```

An empty knowledge table or unknown Technique ID returns an empty list and never fabricates knowledge. Task 7 will populate complete ATT&CK v19.2 chunks and replace the injected work callable with `retrieve_knowledge` hybrid retrieval; the MCP signature, policy layer, audit format, result contract, and server registration remain unchanged.

The Task 6 sentence requiring Evidence conversion applies to event-producing tools. ATT&CK knowledge follows the explicit section 4.3 `list[dict[str, str]]` contract because `EvidenceItem` requires a real security event, event timestamp, and event content hash.

## Policy, limits, deadlines, and retries

Policy validation always runs before storage or search:

- event search: `1 <= limit <= 200`, timezone-aware increasing range, allowlisted filters;
- alert context: nonblank Alert ID and `0 <= before_seconds, after_seconds <= 900`;
- ATT&CK lookup: nonblank query and `1 <= limit <= 10`;
- unknown tool names and malformed known-tool argument sets are denied at the MCP boundary.

Each tool call has a 10-second deadline. Read-only dependency operations may make the initial attempt plus at most two retries for transient timeout/unavailable failures. Evidence persistence is not retried because a database commit failure can have an ambiguous outcome.

## Errors and audit

All client-visible failures use a structured MCP error payload in both `structuredContent` and JSON text content:

```json
{
  "error": {
    "code": "POLICY_DENIED",
    "message": "request denied",
    "trace_id": "TRACE-..."
  }
}
```

Allowed codes are:

- `POLICY_DENIED` for policy, unknown-tool, missing, wrong-type, or extra-argument rejection;
- `NOT_FOUND` for an incident-scoped resource that cannot be resolved;
- `DEPENDENCY_TIMEOUT` for deadline or dependency timeout;
- `DEPENDENCY_UNAVAILABLE` for database/search failures, invalid dependency results, or unclassified internal failures.

Public messages do not expose tracebacks, connection strings, SQL, or raw dependency errors.

Business tools audit calls that reach their implementation. The MCP boundary audits only requests rejected before business invocation, preventing duplicate records. Every audit record contains run ID, tool name, original arguments, success state, error code when present, timestamps, and a result containing trace ID plus either result count or denial reason.

Protocol-invalid raw JSON is handled by the MCP SDK before tool dispatch and remains a JSON-RPC protocol error. Task 6 boundary auditing covers syntactically valid `tools/call` requests with unknown tools or missing, wrong-type, and extra arguments.

## MCP server integration

A restricted `FastMCP` subclass wraps `call_tool` to:

1. check the tool allowlist and exact argument keys;
2. delegate valid requests to FastMCP/Pydantic validation;
3. unwrap domain error codes from the SDK's exception cause chain;
4. return structured error `CallToolResult` values;
5. audit only boundary-level denials.

The production server constructs the three business tool objects, real SQL/OpenSearch work adapters, and one SQL audit writer bound to the validated AgentRun context. Construction remains lazy: tool discovery does not query alerts or knowledge chunks. The existing stdio client continues to keep one child process and one `ClientSession` alive for the entire AgentRun.

## Test and acceptance strategy

Development follows red-green-refactor. Tests cover:

- the existing 201-result, invalid-time, filter, OpenSearch failure, and event audit cases;
- blank, negative, and 901-second alert arguments before dependency access;
- incident/alert ownership, missing alerts, event allowlisting, time filtering, 200-result cap, evidence conversion, timeout, and dependency failures;
- blank/oversized ATT&CK requests, empty results, exact-ID lookup, result shape, result cap, timeout, dependency failure, and no fabricated Technique;
- success and every error code with one audit record per request;
- unknown tools plus missing, wrong-type, and extra arguments denied before work;
- tool schemas hiding run context and discovery returning exactly the three required names;
- a real stdio child-process handshake, three-tool discovery, and structured denial.

Acceptance requires:

- focused Task 6 tests passing;
- the complete backend test suite passing with PostgreSQL and OpenSearch available;
- full backend Ruff and mypy checks passing;
- `git diff --check` passing;
- an independent code review finding no unresolved Critical or Important issues.

## Out of scope

- downloading or vendoring ATT&CK STIX;
- embeddings, pgvector semantic search, reciprocal-rank fusion, Recall@8 evaluation, and citation validation;
- AgentRun orchestration from Task 10;
- Shell execution, arbitrary URL fetching, or any write-capable MCP tool.
