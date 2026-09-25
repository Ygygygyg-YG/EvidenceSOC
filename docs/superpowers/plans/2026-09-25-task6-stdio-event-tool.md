# Task 6: stdio MCP event-tool connection

Scope: Connect the implemented `search_security_events` path as a local MCP stdio server, with one server process and session per AgentRun. The other two specified tools do not yet have implementations and must not be advertised as working.

## Implementation

1. Add failing tests for non-empty run/incident/trace context, database ownership validation, and a fail-closed startup when the AgentRun row is absent or belongs to another incident.
2. Add failing tests that a FastMCP server advertises only `search_security_events`, keeps run context out of its public schema, and delegates a valid call to the existing `SecurityEventTools` implementation.
3. Implement the stdio entry point: load context from process environment; validate the AgentRun row; construct the SQL audit writer and real OpenSearch → EvidenceService work from settings; run FastMCP over stdio without stdout logging; dispose the database engine at exit.
4. Add a client helper that starts the server with explicit run context and dependency settings, keeps a single `ClientSession` open for the AgentRun lifetime, and closes the child process on exit.
5. Exercise a real child-process stdio handshake and tool discovery using a temporary SQLite AgentRun row; run targeted and backend tests, Ruff, and `git diff --check`.

## Boundaries

- Do not register `get_alert_context` or `lookup_attack_technique` until their implementations and policy/audit tests exist.
- Do not claim an end-to-end 10-second deadline or exactly-once evidence write; those are separate remaining Task 6 constraints.
- MCP tool errors still need machine-readable codes, and malformed/unknown-tool requests still need a boundary-level denial audit. The existing `SecurityEventTools` audit covers only requests that reach that implementation.
- The Task 10 AgentRun workflow has not been built yet; it must keep the new client session open for the entire run rather than creating a session per tool call.
- Do not create an isolated worktree: the user explicitly asked to commit and continue in this current worktree, and the just-created baseline commit contains its Task 6 dependencies.
