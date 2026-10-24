"""Synthetic accounts only: no original campaign DB or paid model transport."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import httpx
import pytest
from pydantic import BaseModel

from evals.adapters.model_client import BudgetAccount, BudgetLimit, TrackedModel
from evals.contracts import ModelConfig


def supplement(path, **overrides):
    from evals.adapters.budget_v2 import SupplementBudgetAccount

    binding = {
        "campaign_id": "task13-repair-202610-v2",
        "case_id": "synthetic-case",
        "group": "B3",
        "attempt": 1,
        "purpose": "development",
        "source_sha256": "a" * 64,
        "config_sha256": "b" * 64,
    }
    binding.update(overrides)
    return SupplementBudgetAccount(path, **binding)


def started(request_id="physical-1", **overrides):
    value = {
        "role": "analyze",
        "request_id": request_id,
        "requested_at": datetime.now(UTC).isoformat(),
        "logical_call_id": "logical-1",
        "physical_attempt": 1,
        "request_sha256": "c" * 64,
    }
    value.update(overrides)
    return value


def finished(request_id="physical-1", **overrides):
    value = {
        "request_id": request_id,
        "finished_at": datetime.now(UTC).isoformat(),
        "usage": None,
        "provider_request_id": None,
        "parse_status": "not_received",
        "error_type": "ReadTimeout",
        "usage_missing_reason": "request_or_response_usage_unavailable",
        "duration_ms": 1,
    }
    value.update(overrides)
    return value


@pytest.mark.parametrize("value", [True, False, float("nan"), float("inf"), -1])
def test_base_rejects_nonfinite_boolean_and_negative_money(tmp_path, value):
    with pytest.raises(ValueError):
        BudgetAccount(tmp_path / "invalid.sqlite", total_cny=value)
    account = BudgetAccount(tmp_path / "valid.sqlite")
    with pytest.raises(ValueError):
        account.reserve("bad", value, "development")
    reservation = account.reserve("valid", 0.1, "development")
    with pytest.raises(ValueError):
        account.settle(reservation, value)
    assert account.summary()["in_flight"] == 1


def test_base_rejects_huge_integer_money_as_value_error(tmp_path):
    with pytest.raises(ValueError):
        BudgetAccount(tmp_path / "invalid.sqlite", total_cny=10**1000)


def test_supplement_requires_explicit_frozen_binding_and_metadata(tmp_path):
    path = tmp_path / "budget.sqlite"
    for field in (
        "campaign_id",
        "case_id",
        "group",
        "purpose",
        "source_sha256",
        "config_sha256",
    ):
        with pytest.raises(ValueError):
            supplement(path, **{field: ""})
    for field, value in [
        ("campaign_id", "old-v1"),
        ("attempt", True),
        ("attempt", 0),
        ("purpose", "unknown"),
        ("purpose", "contingency"),
    ]:
        with pytest.raises(ValueError):
            supplement(path, **{field: value})
    account = supplement(path)
    with pytest.raises(ValueError, match="metadata"):
        account.reserve("missing", 0.2, "development")
    assert account.summary()["accounted_cny"] == 0


def test_all_purpose_limits_and_held_contingency_are_atomic(tmp_path):
    path = tmp_path / "budget.sqlite"
    for purpose, phase, limit in [
        ("development", "development", 6),
        ("regression", "formal", 16),
        ("f8", "verification", 6),
    ]:
        account = supplement(path, purpose=purpose)
        account.reserve(purpose, limit, phase, metadata=started(purpose))
        with pytest.raises(BudgetLimit, match=purpose):
            account.reserve(
                purpose + "-overflow",
                0.01,
                phase,
                metadata=started(purpose + "-overflow"),
            )
    summary = account.supplement_summary()
    assert summary["accounted_cny"] == 28
    assert summary["remaining_cny"] == 2
    assert summary["held_contingency_cny"] == 2
    assert summary["dispatchable_cny"] == 0
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0] == 3
        assert db.execute("SELECT COUNT(*) FROM supplement_requests").fetchone()[0] == 3


def test_supplement_and_original_limits_share_the_same_account(tmp_path):
    path = tmp_path / "budget.sqlite"
    original = BudgetAccount(path)
    original.reserve("historic-formal", 80, "formal")
    original.reserve("historic-dev", 12, "development")
    account = supplement(path)
    account.reserve("new-dev", 3, "development", metadata=started("new-dev"))
    with pytest.raises(BudgetLimit, match="development"):
        account.reserve(
            "dev-overflow", 0.1, "development", metadata=started("dev-overflow")
        )
    formal = supplement(path, purpose="regression")
    formal.reserve("new-formal", 5, "formal", metadata=started("new-formal"))
    with pytest.raises(BudgetLimit, match="total"):
        formal.reserve(
            "total-overflow", 0.1, "formal", metadata=started("total-overflow")
        )
    assert original.summary()["accounted_cny"] == 100
    assert formal.supplement_summary()["accounted_cny"] == 8
    assert len(formal.requests()) == 2  # Never infer attribution for historic rows.


def test_unknown_and_inflight_stay_in_purpose_and_campaign_totals_on_reopen(tmp_path):
    path = tmp_path / "budget.sqlite"
    account = supplement(path)
    reservation = account.reserve("unknown", 2, "development", metadata=started())
    account.settle(reservation, None, metadata=finished())
    account.reserve("inflight", 4, "development", metadata=started("physical-2"))
    reopened = supplement(path)
    summary = reopened.supplement_summary()
    assert summary["accounted_cny"] == 6
    assert summary["known_cny"] == 0
    assert summary["unknown_count"] == summary["in_flight"] == 1
    assert summary["unknown_reserved_cny"] == 2
    assert summary["in_flight_reserved_cny"] == 4
    assert summary["purposes"]["development"]["accounted_cny"] == 6
    assert summary["purposes"]["development"]["unknown_count"] == 1
    with pytest.raises(BudgetLimit):
        reopened.reserve("overflow", 0.1, "development", metadata=started("physical-3"))
    for field in ("source_sha256", "config_sha256"):
        with pytest.raises(ValueError, match="frozen"):
            supplement(path, **{field: "d" * 64})
    with pytest.raises(ValueError, match="reset"):
        supplement(path, total_cny=99)


def test_multiple_instances_cannot_overrun_any_purpose_or_leave_orphans(tmp_path):
    path = tmp_path / "budget.sqlite"
    supplement(path)

    def reserve(index):
        try:
            return supplement(path, case_id=f"case-{index}").reserve(
                str(index), 2, "development", metadata=started(str(index))
            )
        except BudgetLimit:
            return None

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(reserve, range(12)))
    assert sum(value is not None for value in results) == 3
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0] == 3
        assert db.execute("SELECT COUNT(*) FROM supplement_requests").fetchone()[0] == 3


@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        started(role=""),
        started(requested_at="not-time"),
        started(requested_at="2026-10-23T01:00:00"),
        started(physical_attempt=True),
        started(extra="untrusted"),
        started(request_sha256="invalid"),
    ],
)
def test_invalid_start_metadata_never_leaves_a_global_reservation(tmp_path, bad):
    account = supplement(tmp_path / "budget.sqlite")
    with pytest.raises(ValueError, match="metadata"):
        account.reserve("bad", 1, "development", metadata=bad)
    assert account.summary()["accounted_cny"] == 0
    assert account.requests() == []


def test_mismatched_phase_duplicate_ids_and_settlement_binding_fail_closed(tmp_path):
    account = supplement(tmp_path / "budget.sqlite")
    with pytest.raises(ValueError, match="phase"):
        account.reserve("bad-phase", 1, "formal", metadata=started())
    reservation = account.reserve("one", 1, "development", metadata=started())
    with pytest.raises((BudgetLimit, ValueError), match="already|duplicate"):
        account.reserve("one", 1, "development", metadata=started("other"))
    with pytest.raises((BudgetLimit, ValueError), match="already|duplicate"):
        account.reserve("other", 1, "development", metadata=started())
    with pytest.raises(ValueError, match="metadata"):
        account.settle(reservation, 0.2)
    with pytest.raises(ValueError, match="request"):
        account.settle(reservation, 0.2, metadata=finished("different"))
    with pytest.raises(ValueError, match="binding"):
        supplement(account.path, case_id="other").settle(
            reservation, 0.2, metadata=finished()
        )
    assert account.summary()["accounted_cny"] == 1
    assert account.summary()["in_flight"] == 1


def test_settlements_persist_usage_unknowns_and_overbound_global_halt(tmp_path):
    path = tmp_path / "budget.sqlite"
    account = supplement(path)
    reservation = account.reserve("one", 0.1, "development", metadata=started())
    usage = {"prompt_tokens": 4, "completion_tokens": 2}
    with pytest.raises(BudgetLimit, match="exceeded"):
        account.settle(
            reservation,
            0.2,
            metadata=finished(
                usage=usage, provider_request_id="provider-1", usage_missing_reason=None
            ),
        )
    row = account.requests()[0]
    assert row["campaign_id"] == "task13-repair-202610-v2"
    assert row["case_id"] == "synthetic-case"
    assert row["group"] == "B3"
    assert row["attempt"] == 1
    assert row["role"] == "analyze"
    assert row["request_id"] == "physical-1"
    assert row["provider_request_id"] == "provider-1"
    assert row["usage"] == usage
    assert row["finished_at"] >= row["requested_at"]
    assert row["cost_cny"] == 0.2
    assert supplement(path).summary()["halted"] is True
    with pytest.raises(RuntimeError, match="halt"):
        BudgetAccount(path).reserve("v1-after-halt", 0.1, "formal")


@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        finished(duration_ms=True),
        finished(parse_status=[]),
        finished(usage={"prompt_tokens": float("nan")}),
        finished(finished_at="2000-01-01T00:00:00Z"),
        finished(usage_missing_reason=None),
        finished(extra=True),
    ],
)
def test_invalid_settlement_rolls_back_both_accounting_and_metadata(tmp_path, bad):
    account = supplement(tmp_path / "budget.sqlite")
    reservation = account.reserve("one", 1, "development", metadata=started())
    if bad and bad.get("finished_at") != "2000-01-01T00:00:00Z":
        bad = {**bad, "finished_at": datetime.now(UTC).isoformat()}
    with pytest.raises(ValueError, match="metadata"):
        account.settle(reservation, None, metadata=bad)
    assert account.summary()["accounted_cny"] == 1
    assert account.summary()["in_flight"] == 1
    assert account.requests()[0]["finished_at"] is None


def test_known_cost_releases_unused_bound_and_zero_charge_is_observed(tmp_path):
    account = supplement(tmp_path / "budget.sqlite")
    reservation = account.reserve("one", 6, "development", metadata=started())
    account.settle(
        reservation,
        0,
        metadata=finished(
            usage={"prompt_tokens": 0, "completion_tokens": 0},
            usage_missing_reason=None,
        ),
    )
    account.reserve("two", 6, "development", metadata=started("physical-2"))
    summary = account.supplement_summary()
    assert summary["accounted_cny"] == 6
    assert summary["unknown_count"] == 0
    assert summary["in_flight"] == 1
    with pytest.raises(ValueError, match="already settled"):
        account.settle(
            reservation, 0, metadata=finished(usage={}, usage_missing_reason=None)
        )


def test_unbound_v1_account_cannot_settle_a_v2_request(tmp_path):
    account = supplement(tmp_path / "budget.sqlite")
    reservation = account.reserve("one", 1, "development", metadata=started())
    with pytest.raises(ValueError, match="bound"):
        BudgetAccount(account.path).settle(reservation, 0)
    assert account.summary()["in_flight"] == 1


def test_dispatchable_summary_respects_original_caps_and_global_halt(tmp_path):
    path = tmp_path / "budget.sqlite"
    original = BudgetAccount(path)
    original.reserve("historic", 98, "formal")
    account = supplement(path)
    assert account.supplement_summary()["dispatchable_cny"] == 2
    original.halt_provider(402)
    assert account.supplement_summary()["dispatchable_cny"] == 0


class Answer(BaseModel):
    verdict: str


@pytest.mark.asyncio
async def test_v2_refuses_model_dispatch_without_explicit_stable_call_id(tmp_path):
    sent = []
    client = TrackedModel(
        ModelConfig(),
        api_key="synthetic",
        account=supplement(tmp_path / "budget.sqlite"),
        phase="development",
        transport=httpx.MockTransport(lambda request: sent.append(request)),
    )
    with pytest.raises(ValueError, match="explicit stable"):
        await client.structured("analyze", Answer, {})
    assert sent == []
    assert client.account.requests() == []


@pytest.mark.asyncio
async def test_tracked_model_records_physical_attempts_unknowns_and_no_replay(tmp_path):
    path = tmp_path / "budget.sqlite"
    sent = []

    def respond(request):
        sent.append(request)
        if len(sent) == 1:
            raise httpx.ReadTimeout("synthetic", request=request)
        return httpx.Response(
            200,
            json={
                "id": "provider-2",
                "model": "synthetic-v1",
                "usage": {"prompt_tokens": 20, "completion_tokens": 5},
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": '{"verdict":"attack"}'},
                    }
                ],
            },
        )

    def model():
        return TrackedModel(
            ModelConfig(),
            api_key="synthetic",
            account=supplement(path),
            phase="development",
            transport=httpx.MockTransport(respond),
        )

    client = model()
    state = {"_model_call_id": "explicit-logical-1"}
    with pytest.raises(httpx.ReadTimeout):
        await client.structured("analyze", Answer, state)
    await client.structured("analyze", Answer, state)
    rows = client.account.requests()
    assert len(rows) == len(client.ledger) == len(sent) == 2
    assert [row["physical_attempt"] for row in rows] == [1, 2]
    assert len({row["request_id"] for row in rows}) == 2
    assert rows[0]["cost_cny"] is None
    assert rows[0]["usage_missing_reason"]
    assert rows[0]["error_type"] == "ReadTimeout"
    assert rows[1]["usage"] == {"prompt_tokens": 20, "completion_tokens": 5}
    assert rows[1]["cost_cny"] > 0
    assert all(row["requested_at"] and row["finished_at"] for row in rows)
    assert all(row["campaign_id"] == "task13-repair-202610-v2" for row in client.ledger)
    assert {row["physical_request_id"] for row in client.ledger} == {
        row["request_id"] for row in rows
    }
    with pytest.raises(BudgetLimit, match="already"):
        await model().structured("analyze", Answer, state)
    assert len(sent) == 2
