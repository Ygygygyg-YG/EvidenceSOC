"""Offline regression tests for reviewed deadline and systemic-failure boundaries."""

import asyncio
from datetime import timedelta
from types import SimpleNamespace

import pytest

from evals.tests.test_verification_v2 import (
    setup as verification_setup,
)
from evals.tests.test_verification_v2 import (
    timing,
    verifier,
    worker_value,
)


@pytest.fixture
def setup(tmp_path):
    return verification_setup.__wrapped__(tmp_path)


@pytest.mark.parametrize("cross_during", ["timing", "inputs"])
def test_final_deadline_crossing_never_binds_or_dispatches(
    setup, monkeypatch, cross_during
):
    m, store, source, now, _, _ = setup
    current = [now]
    calls = []
    original_timing, original_write = m.observed_timing_max, m._immutable

    def slow_timing(*args):
        result = original_timing(*args)
        if cross_during == "timing":
            current[0] = now + timedelta(seconds=2)
        return result

    def slow_write(path, value):
        result = original_write(path, value)
        if cross_during == "inputs" and path.parent.name == "inputs":
            current[0] = now + timedelta(seconds=2)
        return result

    async def worker(request):
        calls.append(request)
        return worker_value(request)

    monkeypatch.setattr(m, "observed_timing_max", slow_timing)
    monkeypatch.setattr(m, "_immutable", slow_write)
    with pytest.raises(PermissionError, match="deadline"):
        asyncio.run(
            store.run_case(
                source["case_id"],
                source,
                worker=worker,
                timing_receipt=timing(store, source, now),
                approval_verifier=verifier,
                now=lambda: current[0],
                admission_deadline=now + timedelta(seconds=1),
            )
        )
    assert calls == []
    assert store.snapshot()["cases"][source["case_id"]]["binding"] is None


def test_admitted_case_may_finish_after_global_deadline(setup):
    _, store, source, now, _, _ = setup
    current, calls = [now], []

    async def worker(request):
        calls.append(request)
        current[0] = now + timedelta(seconds=2)
        return worker_value(request)

    result = asyncio.run(
        store.run_case(
            source["case_id"],
            source,
            worker=worker,
            timing_receipt=timing(store, source, now),
            approval_verifier=verifier,
            now=lambda: current[0],
            admission_deadline=now + timedelta(seconds=1),
        )
    )
    assert len(calls) == 6
    assert all(
        row["status"] == "completed"
        for row in result["records"]
        if row["case_id"] == source["case_id"]
    )


def test_invalid_f8_receipt_is_systemic_stop_not_ordinary_gap(monkeypatch):
    from datetime import datetime, timezone

    from evals import task13_rolling as rolling
    from evals import verification, verification_v2

    native = object.__new__(rolling.NativeRollingOperations)
    case = "ait-" + "1" * 24
    native.identity, native.data = {}, {"e_timing_receipt": {}}
    native._save = lambda *args: None
    rows = [{"case_id": case, "status": "failed", "reason": "worker_receipt_invalid"}]
    rows += [
        {"case_id": case, "status": "not_started", "reason": None} for _ in range(5)
    ]

    async def run_case(*args, **kwargs):
        return {"records": rows}

    native.campaign = SimpleNamespace(run_case=run_case)
    monkeypatch.setattr(verification, "_eligibility", lambda *args: (None, None))
    monkeypatch.setattr(verification_v2, "observed_timing_max", lambda *args: 1.0)
    source = {
        "state": {
            "response_plan": {
                "expires_at": (
                    datetime.now(timezone.utc) + timedelta(minutes=20)
                ).isoformat()
            }
        }
    }
    with pytest.raises(PermissionError, match="receipt|systemic|isolation"):
        asyncio.run(native.run_f8(case, {"source": source, "receipt": {}}))
