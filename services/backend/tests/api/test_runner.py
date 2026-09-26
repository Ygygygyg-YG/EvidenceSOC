import asyncio

import pytest

from evidencesoc.api.runner import InvestigationRunner


class Store:
    def __init__(self):
        self.metadata = {
            "investigation_id": "IV-test",
            "incident_id": "IN-test",
            "trace_id": "TRACE-test",
            "created_at": "2026-09-26T00:00:00+00:00",
            "state": {},
            "status": "received",
        }
        self.events = []

    def get_investigation(self, identifier):
        return self.metadata

    def append_event(self, identifier, event, data, key):
        self.events.append({"event": event, "data": data, "key": key})
        return self.events[-1]

    def save_state(self, identifier, state):
        self.metadata.update(state=state, status=state["status"])

    def finalize(self, identifier, state, event, data):
        result = self.append_event(identifier, event, data, "terminal")
        self.save_state(identifier, state)
        return result


@pytest.mark.asyncio
async def test_worker_retries_shared_workflow_lock_instead_of_losing_job():
    store = Store()

    class Workflow:
        attempts = 0

        async def get_state(self, incident_id):
            return {"status": "completed", "events": []}

        async def stream_events(self, incident_id, **kwargs):
            self.attempts += 1
            if self.attempts == 1:
                raise ValueError("investigation is already running")
            if False:
                yield

    workflow = Workflow()
    runner = InvestigationRunner(store, workflow)
    await asyncio.wait_for(runner.run("IV-test"), timeout=2)
    assert workflow.attempts == 2
    assert store.metadata["status"] == "completed"
    assert store.events[-1]["event"] == "investigation.completed"


@pytest.mark.asyncio
async def test_terminal_failure_uses_atomic_finalize():
    store = Store()
    finalized = []
    original = store.finalize

    def finalize(*args):
        finalized.append(args)
        return original(*args)

    store.finalize = finalize

    class Workflow:
        async def get_state(self, incident_id):
            raise RuntimeError("password=never-emit-this")

    runner = InvestigationRunner(store, Workflow())
    await runner.run("IV-test")
    assert len(finalized) == 1
    assert store.metadata["status"] == "failed"
    assert "never-emit-this" not in str(store.events)


@pytest.mark.asyncio
async def test_decision_arriving_as_job_finishes_is_scheduled_again():
    store = Store()
    runner = InvestigationRunner(store, None)
    entered, release = asyncio.Event(), asyncio.Event()
    calls = []

    async def run(identifier):
        calls.append(identifier)
        if len(calls) == 1:
            entered.set()
            await release.wait()

    runner.run = run
    runner.schedule(store.metadata)
    await entered.wait()
    runner.schedule(store.metadata)
    release.set()
    for _ in range(100):
        if len(calls) == 2:
            break
        await asyncio.sleep(0.005)
    assert len(calls) == 2
    await runner.close()
