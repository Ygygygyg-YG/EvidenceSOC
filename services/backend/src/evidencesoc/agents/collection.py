"""Bounded, recoverable tool selection inside the collection role."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Literal

from pydantic import ValidationError

from evidencesoc.agents.collect_policy import (
    CollectionDecision,
    validate_collection_call,
)
from evidencesoc.tools.ledger import (
    AttemptLimitExceeded,
    BudgetExceeded,
    Ledger,
    LedgerReservation,
    query_fingerprint,
)
from evidencesoc.tools.policy import PolicyDeniedError


class BoundedCollector:
    def __init__(
        self,
        *,
        ledger: Ledger,
        invoke: Callable[[str, dict[str, Any]], Awaitable[list[dict[str, Any]]]],
        scope: dict[str, Any],
        state: Mapping[str, Any],
        run_id: str,
        model: Any | None,
        llm_mode: str,
        model_timeout: float = 60.0,
    ) -> None:
        self.ledger = ledger
        self.invoke = invoke
        self.scope = scope
        self.state = state
        self.run_id = run_id
        self.model = model
        self.llm_mode = llm_mode
        self.model_timeout = model_timeout
        self.incident_id = str(state["incident_id"])
        self.round_no = int(state.get("fallback_count", 0)) + 1
        self.values: list[dict[str, Any]] = []
        self.knowledge: list[dict[str, Any]] = []
        self.observations: list[dict[str, Any]] = []
        self.model_attempts = 0
        self.fallback_used = llm_mode == "fixture"
        self.seen_ids: set[str] = set()
        self.touched_rows: dict[str, LedgerReservation] = {}
        self.attempted_queries: set[str] = set()
        self.seen_evidence_ids: set[str] = set()
        self.seen_knowledge_ids: set[str] = set()
        self.no_new_streak = 0

    async def _ledger(self, name: str, *args: Any, **kwargs: Any) -> Any:
        return await asyncio.to_thread(getattr(self.ledger, name), *args, **kwargs)

    def _record_result(
        self,
        row: LedgerReservation,
        *,
        count_streak: bool = True,
        track_row: bool = True,
    ) -> None:
        if row.call_id in self.seen_ids:
            return
        self.seen_ids.add(row.call_id)
        if track_row:
            self.touched_rows[row.call_id] = row
        if row.status == "completed":
            result = row.result or {}
            values = result.get("values", []) if isinstance(result, dict) else []
            new_count = 0
            if row.tool_name == "lookup_attack_technique":
                for item in values:
                    identity = item.get("knowledge_chunk_id")
                    if identity not in self.seen_knowledge_ids:
                        self.knowledge.append(item)
                        if identity is not None:
                            self.seen_knowledge_ids.add(identity)
                        new_count += 1
            else:
                for item in values:
                    identity = item.get("evidence_id")
                    if identity not in self.seen_evidence_ids:
                        self.values.append(item)
                        if identity is not None:
                            self.seen_evidence_ids.add(identity)
                        new_count += 1
            if count_streak:
                self.no_new_streak = 0 if new_count else self.no_new_streak + 1
            self.observations.append(
                {
                    "call_id": row.call_id,
                    "tool_name": row.tool_name,
                    "status": "completed",
                    "result_count": len(values),
                    "new_count": new_count,
                    "rationale": row.rationale,
                }
            )
        elif row.status == "failed":
            if count_streak:
                self.no_new_streak += 1
            self.observations.append(
                {
                    "call_id": row.call_id,
                    "tool_name": row.tool_name,
                    "status": "failed",
                    "error_code": row.error_code,
                    "rationale": row.rationale,
                }
            )

    async def _execute(
        self, row: LedgerReservation, *, count_streak: bool = True
    ) -> LedgerReservation:
        try:
            arguments = validate_collection_call(
                row.tool_name, row.arguments, self.scope
            )
        except (PolicyDeniedError, ValueError, TypeError, KeyError):
            failed = await self._ledger("fail", row.call_id, "POLICY_DENIED")
            self._record_result(failed, count_streak=count_streak)
            return failed
        while True:
            try:
                attempt = await self._ledger("begin_attempt", row.call_id)
            except AttemptLimitExceeded:
                failed = await self._ledger("fail", row.call_id, "ATTEMPTS_EXHAUSTED")
                self._record_result(failed, count_streak=count_streak)
                return failed
            try:
                values = await asyncio.wait_for(
                    self.invoke(row.tool_name, arguments), timeout=10.0
                )
            except TimeoutError:
                code = "DEPENDENCY_TIMEOUT"
            except Exception as exc:  # noqa: BLE001 - sanitize MCP errors for the model.
                message = str(exc)
                code = (
                    message.rsplit(": ", 1)[-1]
                    if message.startswith("MCP tool failed: ")
                    else "DEPENDENCY_UNAVAILABLE"
                )
                if code not in {
                    "DEPENDENCY_TIMEOUT",
                    "DEPENDENCY_UNAVAILABLE",
                    "NOT_FOUND",
                    "POLICY_DENIED",
                    "MCP_TOOL_ERROR",
                }:
                    code = "DEPENDENCY_UNAVAILABLE"
            else:
                completed = await self._ledger(
                    "complete", row.call_id, {"values": values}
                )
                self._record_result(completed, count_streak=count_streak)
                return completed
            if code in {"POLICY_DENIED", "NOT_FOUND"} or attempt.attempts >= 3:
                failed = await self._ledger("fail", row.call_id, code)
                self._record_result(failed, count_streak=count_streak)
                return failed

    async def _call(
        self, tool_name: str, arguments: dict[str, Any], rationale: str
    ) -> Literal["called", "duplicate_query", "budget_exhausted"]:
        try:
            canonical = validate_collection_call(tool_name, arguments, self.scope)
        except (PolicyDeniedError, ValueError, TypeError, KeyError):
            canonical = arguments
        fingerprint = query_fingerprint(tool_name, canonical)
        if fingerprint in self.attempted_queries:
            return "duplicate_query"
        try:
            row = await self._ledger(
                "reserve",
                self.incident_id,
                self.run_id,
                self.round_no,
                tool_name,
                canonical,
                rationale,
            )
        except BudgetExceeded:
            return "budget_exhausted"
        self.attempted_queries.add(fingerprint)
        if row.reused and row.status in {"completed", "failed"}:
            self._record_result(
                row, count_streak=getattr(row, "source_call_id", None) is None
            )
            return "duplicate_query"
        if row.status in {"reserved", "running"}:
            await self._execute(row)
        return "called"

    def _rule(self) -> CollectionDecision:
        prior_tools = {
            item["tool_name"]
            for item in self.observations
            if item.get("tool_name") is not None
        }
        if self.scope["filters"] and "search_security_events" not in prior_tools:
            return CollectionDecision(
                action="call",
                tool_name="search_security_events",
                arguments={
                    key: self.scope[key]
                    for key in ("time_from", "time_to", "filters", "limit")
                },
                rationale="Search only the incident's observed entities and time window.",
            )
        if "lookup_attack_technique" not in prior_tools:
            summaries = [str(item.get("summary", "")) for item in self.values[:3]]
            title = str((self.state.get("alerts") or [{}])[0].get("title", ""))
            query = (
                "SQL injection exploit public facing application"
                if "sql injection" in title.casefold()
                else " ".join([title, *summaries]).strip()[:300]
            )
            if not query:
                query = "observed attack technique"
            return CollectionDecision(
                action="call",
                tool_name="lookup_attack_technique",
                arguments={"query": query, "limit": 8},
                rationale="Look up relevant public attack knowledge for observed activity.",
            )
        return CollectionDecision(
            action="stop", rationale="No further evidence gap in the rule plan."
        )

    async def _plan(self, remaining: int) -> CollectionDecision:
        if self.llm_mode == "fixture":
            return self._rule()
        if self.model is None:
            self.fallback_used = True
            return self._rule()
        context = {
            "incident_id": self.incident_id,
            "alerts": self.state.get("alerts", []),
            "collection_context": {
                "allowed_tools": [
                    "get_alert_context",
                    "search_security_events",
                    "lookup_attack_technique",
                ],
                "scope": self.scope,
                "remaining_logical_calls": remaining,
                "observations": self.observations,
                "evidence_summaries": [
                    {
                        "evidence_id": item.get("evidence_id"),
                        "summary": item.get("summary"),
                    }
                    for item in self.values[:20]
                ],
            },
        }
        code = "MODEL_UNAVAILABLE"
        for _ in range(3):
            self.model_attempts += 1
            try:
                output = await asyncio.wait_for(
                    self.model.structured("collect", CollectionDecision, context),
                    timeout=self.model_timeout,
                )
                return CollectionDecision.model_validate(output)
            except TimeoutError:
                code = "MODEL_TIMEOUT"
            except (ValidationError, ValueError):
                code = "MODEL_INVALID_OUTPUT"
            except Exception:  # noqa: BLE001 - model failures use bounded rule fallback.
                code = "MODEL_UNAVAILABLE"
            self.observations.append(
                {
                    "status": "planner_retry",
                    "attempt": self.model_attempts,
                    "error_code": code,
                }
            )
        self.fallback_used = True
        self.observations.append({"status": "planner_fallback", "error_code": code})
        return self._rule()

    async def _report(self, stop_reason: str) -> dict[str, Any]:
        summary = await self._ledger("summary", self.incident_id, self.round_no)
        rows = await self._ledger("calls", self.incident_id, self.round_no)
        referenced_rows = {row.call_id: row for row in rows}
        referenced_rows.update(self.touched_rows)
        return {
            "evidence_values": self.values,
            "knowledge": self.knowledge,
            "collection_round": self.round_no,
            "collection_budget_used": summary.total_used,
            "collection_round_used": summary.round_used,
            "collection_ledger_ids": list(referenced_rows),
            "collection_tool_attempts": sum(
                row.attempts for row in referenced_rows.values()
            ),
            "collection_model_attempts": self.model_attempts,
            "collection_observations": self.observations,
            "collection_stop_reason": stop_reason,
            "fallback_used": self.fallback_used,
        }

    async def run(self) -> dict[str, Any]:
        for prior_round in range(1, self.round_no):
            older = await self._ledger("calls", self.incident_id, prior_round)
            for row in older:
                if row.status in {"reserved", "running"}:
                    self.attempted_queries.add(row.fingerprint)
                    recovered = await self._execute(row, count_streak=False)
                    if recovered.status == "failed":
                        return await self._report("recovery_failed")
                elif row.status == "completed":
                    self._record_result(row, count_streak=False, track_row=False)
        previous = await self._ledger("calls", self.incident_id, self.round_no)
        for row in previous:
            self.attempted_queries.add(row.fingerprint)
            if row.status in {"reserved", "running"}:
                recovered = await self._execute(row)
                if recovered.status == "failed":
                    return await self._report("recovery_failed")
            else:
                self._record_result(row, count_streak=row.source_call_id is None)
        seed = {
            "alert_id": self.scope["alert_id"],
            "before_seconds": 900,
            "after_seconds": 900,
        }
        seed_outcome = await self._call(
            "get_alert_context", seed, "Read the fixed incident alert context."
        )
        if seed_outcome == "budget_exhausted":
            return await self._report("budget_exhausted")
        stop_reason = "completed"
        for _ in range(3):
            summary = await self._ledger("summary", self.incident_id, self.round_no)
            remaining = min(summary.round_remaining, summary.total_remaining)
            if remaining == 0:
                stop_reason = "budget_exhausted"
                break
            if self.no_new_streak >= 2:
                stop_reason = "no_new_evidence"
                break
            decision = await self._plan(remaining)
            if decision.action == "stop":
                stop_reason = "planner_stopped"
                break
            assert decision.tool_name is not None
            outcome = await self._call(
                decision.tool_name, decision.arguments, decision.rationale
            )
            if outcome != "called":
                stop_reason = outcome
                break
        return await self._report(stop_reason)
