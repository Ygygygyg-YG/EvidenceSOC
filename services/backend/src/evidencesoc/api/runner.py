from __future__ import annotations

import asyncio
from typing import Any

import structlog

from evidencesoc.agents.graph import TERMINAL_STATES
from evidencesoc.api.errors import ApiError
from evidencesoc.logging import redact

logger = structlog.get_logger(__name__)


def public_output(value: dict[str, Any]) -> dict[str, Any]:
    def clean(item):
        if isinstance(item, dict):
            return {key: clean(nested) for key, nested in item.items() if key != "raw"}
        if isinstance(item, list):
            return [clean(nested) for nested in item]
        return item

    return redact(clean(value))


class InvestigationRunner:
    """Own workflow jobs; HTTP and SSE connections only read durable state."""

    def __init__(self, store, workflow):
        self.store = store
        self.workflow = workflow
        self.tasks: dict[str, asyncio.Task] = {}
        self.rerun: set[str] = set()
        self.closed = False

    async def call(self, name: str, *args, **kwargs):
        return await asyncio.to_thread(getattr(self.store, name), *args, **kwargs)

    async def publish(self, metadata, event, data, key):
        return await self.call(
            "append_event",
            metadata["investigation_id"],
            event,
            self.event_data(metadata, data),
            key,
        )

    @staticmethod
    def event_data(metadata, data):
        return {
            **public_output(data),
            "incident_id": metadata["incident_id"],
            "investigation_id": metadata["investigation_id"],
            "trace_id": metadata["trace_id"],
        }

    async def start(self, metadata):
        if self.workflow is None:
            raise ApiError(
                503, "DEPENDENCY_UNAVAILABLE", "Workflow dependencies are not ready."
            )
        await self.publish(
            metadata,
            "investigation.started",
            {"status": "received", "occurred_at": metadata["created_at"]},
            "started",
        )
        self.schedule(metadata)

    def schedule(self, metadata):
        identifier = metadata["investigation_id"]
        existing = self.tasks.get(identifier)
        if self.closed:
            return
        if existing is not None and not existing.done():
            self.rerun.add(identifier)
            return
        task = asyncio.create_task(
            self.run(identifier), name=f"investigation:{identifier}"
        )
        self.tasks[identifier] = task

        def finished(completed):
            if self.tasks.get(identifier) is completed:
                self.tasks.pop(identifier, None)
                if identifier in self.rerun:
                    self.rerun.discard(identifier)
                    self.schedule(metadata)
            if not completed.cancelled() and completed.exception() is not None:
                logger.error(
                    "investigation_job_failed",
                    investigation_id=identifier,
                    error_type=type(completed.exception()).__name__,
                )

        task.add_done_callback(finished)

    async def recover(self):
        for metadata in await self.call("list_recoverable"):
            active = self.tasks.get(metadata["investigation_id"])
            if active is not None and not active.done():
                continue
            if (
                metadata["status"] == "awaiting_approval"
                and metadata["state"].get("response_plan")
                and not metadata["state"].get("pending_decision")
            ):
                continue
            await self.start(metadata)

    async def record_decision(self, metadata):
        command = metadata["state"].get("pending_decision")
        if command:
            await self.publish(
                metadata,
                "decision.recorded",
                self.decision_data(command),
                "decision:" + command["response_plan_id"],
            )

    @staticmethod
    def decision_data(command):
        return {
            key: command[key]
            for key in ("response_plan_id", "decision", "reason", "decided_by")
        }

    async def translate(self, metadata, event):
        kind, node = event["event"], event["node"]
        source_id = event.get("event_uuid", event["event_id"])
        output = event.get("output") or {}
        data = {"agent": node, "occurred_at": event["occurred_at"], "output": output}
        if kind == "node.started":
            await self.publish(
                metadata, "agent.started", data, f"source:{source_id}:started"
            )
        elif kind in {"node.completed", "node.failed"}:
            for item in output.get("evidence", []):
                await self.publish(
                    metadata,
                    "evidence.added",
                    {"evidence": item},
                    "evidence:" + item["evidence_id"],
                )
            await self.publish(
                metadata,
                "agent.completed",
                {**data, "status": "failed" if kind == "node.failed" else "completed"},
                f"source:{source_id}:completed",
            )
            if output.get("validation_result"):
                await self.publish(
                    metadata,
                    "validation.completed",
                    {"validation_result": output["validation_result"]},
                    "validation",
                )
        elif kind == "approval.decided":
            await self.publish(
                metadata,
                "decision.recorded",
                self.decision_data(output),
                "decision:" + output["response_plan_id"],
            )

    async def finish(self, metadata, state):
        for event in state.get("events", []):
            await self.translate(metadata, event)
        state = {**state, "trace_id": metadata["trace_id"]}
        if state["status"] == "awaiting_approval":
            await self.publish(
                metadata,
                "approval.required",
                {"response_plan": state["response_plan"], "status": state["status"]},
                "approval:" + state["response_plan"]["response_plan_id"],
            )
        elif state["status"] in TERMINAL_STATES:
            kind = (
                "investigation.failed"
                if state["status"] in {"failed", "manual_review"}
                else "investigation.completed"
            )
            await self.call(
                "finalize",
                metadata["investigation_id"],
                state,
                kind,
                self.event_data(
                    metadata,
                    {
                        "status": state["status"],
                        "stop_reason": state.get("stop_reason"),
                        "errors": state.get("errors", []),
                    },
                ),
            )
            return
        await self.call("save_state", metadata["investigation_id"], state)

    async def run(self, identifier):
        while not self.closed:
            if await self.run_once(identifier):
                return
            await asyncio.sleep(0.1)

    async def run_once(self, identifier):
        metadata = await self.call("get_investigation", identifier)
        try:
            command = metadata["state"].get("pending_decision")
            state = await self.workflow.get_state(metadata["incident_id"])
            if command:
                await self.record_decision(metadata)
            if (
                command
                and state.get("status") == "awaiting_approval"
                and not state.get("approval")
            ):
                iterator = self.workflow.stream_approval(
                    metadata["incident_id"],
                    response_plan_id=command["response_plan_id"],
                    decision=command["decision"],
                    reason=command["reason"],
                    decided_by=command["decided_by"],
                )
            else:
                iterator = self.workflow.stream_events(
                    metadata["incident_id"], trace_id=metadata["trace_id"]
                )
            async for event in iterator:
                await self.translate(metadata, event)
            state = await self.workflow.get_state(metadata["incident_id"])
            await self.finish(metadata, state)
        except asyncio.CancelledError:
            raise  # Startup resumes the last durable checkpoint.
        except Exception as error:  # noqa: BLE001 -- provider details must never escape
            if (
                isinstance(error, ValueError)
                and str(error) == "investigation is already running"
            ):
                return False
            logger.error(
                "investigation_failed",
                investigation_id=identifier,
                trace_id=metadata["trace_id"],
                error_type=type(error).__name__,
            )
            failure = {
                **metadata["state"],
                "incident_id": metadata["incident_id"],
                "trace_id": metadata["trace_id"],
                "status": "failed",
                "errors": [{"code": "DEPENDENCY_UNAVAILABLE"}],
                "stop_reason": "dependency_unavailable",
            }
            await self.call(
                "finalize",
                identifier,
                failure,
                "investigation.failed",
                self.event_data(
                    metadata, {"status": "failed", "code": "DEPENDENCY_UNAVAILABLE"}
                ),
            )
        return True

    async def close(self):
        self.closed = True
        tasks = list(self.tasks.values())
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.tasks.clear()
        self.rerun.clear()
