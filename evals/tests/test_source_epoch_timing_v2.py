"""Native synthetic journals only; no live services, source epochs or budget writes."""

import asyncio
import json
from contextlib import ExitStack

import pytest

from evals.adapters.source_epochs import _lock_controller_roots
from evals.contracts import canonical_hash
from evals.e_timing import read_timing_journal
from evals.tests.test_e_timing_replicates import (
    approved_source,
    value_for,
)
from evals.tests.test_e_timing_replicates import (
    setup as timing_setup,
)
from evals.verification_v2 import _json_bytes


@pytest.fixture
def timing(tmp_path):
    store, clock, _ = timing_setup.__wrapped__(tmp_path)
    assert store.registration["schema_version"] == "task13-e-timing-registration-v2"
    return store, clock


def files(root):
    return {
        path.relative_to(root): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def check_roots(*roots):
    with ExitStack() as stack:
        _lock_controller_roots({str(root.resolve()) for root in roots}, stack)
        for root in roots:
            assert (root / ".writer-lock").is_dir()
            assert (root / ".analysis36-campaign-lock").is_dir()


def assert_rejected_without_writes(root, message):
    before = files(root)
    with pytest.raises(PermissionError, match=message) as refused:
        check_roots(root)
    assert files(root) == before
    assert not (root / ".writer-lock").exists()
    assert not (root / ".analysis36-campaign-lock").exists()
    return refused.value


def test_completed_v2_native_journal_is_quiescent_and_read_only(timing):
    store, clock = timing
    requests = []

    async def worker(request):
        requests.append(request)
        clock.advance(3)
        return value_for(request)

    async def complete():
        for index, trial in enumerate(store.registration["trials"]):
            await store.run_trial(
                trial["trial_id"],
                approved_source(store, index, clock),
                run_worker=worker,
            )

    asyncio.run(complete())
    state = read_timing_journal(store.root)
    assert len(requests) == len(state["records"]) == 18
    assert len(state["cases"]) == 3
    assert {row["status"] for row in state["cases"].values()} == {"completed"}
    assert {row["status"] for row in state["records"].values()} == {"completed"}
    before = files(store.root)
    check_roots(store.root)
    assert files(store.root) == before
    assert not list(store.root.rglob(".writer-lock"))
    assert not list(store.root.rglob(".analysis36-campaign-lock"))


def test_not_started_v2_native_journal_is_quiescent(timing):
    store, _ = timing
    before = files(store.root)
    check_roots(store.root)
    assert files(store.root) == before


@pytest.mark.parametrize("status", ["failed", "expired", "rejected", "not_applicable"])
def test_v2_terminal_trial_and_branch_remain_quiescent(timing, status):
    store, _ = timing
    trial, request = next(iter(store.trials)), next(iter(store.records))
    store._append(
        {
            "kind": "synthetic-terminal",
            "trial_id": trial,
            "trial_patch": {"status": status},
            "request_id": request,
            "branch_patch": {"status": status},
        }
    )
    before = files(store.root)
    check_roots(store.root)
    assert files(store.root) == before


@pytest.mark.parametrize("row", ["trial", "branch"])
@pytest.mark.parametrize(
    "status", ["dispatched", "unknown", "running", "pending_approval"]
)
def test_v2_unresolved_status_cannot_hide_behind_stale_projection(timing, row, status):
    store, _ = timing
    trial, request = next(iter(store.trials)), next(iter(store.records))
    store._append(
        {
            "kind": "synthetic-unresolved",
            "trial_id": trial,
            "request_id": request,
            f"{row}_patch": {"status": "unknown"},
        }
    )
    event_path = max((store.root / "events").glob("*.json"))
    event = json.loads(event_path.read_bytes())
    event["payload"][f"{row}_patch"]["status"] = status
    # Keep the chain valid: unsupported states must fail the native status gate.
    event_path.unlink()
    (
        store.root / "events" / f"{event['sequence']:08d}-{canonical_hash(event)}.json"
    ).write_bytes(_json_bytes(event))
    (store.root / "latest.json").write_text('{"status":"completed"}', encoding="utf-8")
    message = (
        "E journal is invalid"
        if status in {"running", "pending_approval"}
        else "not quiescent|pending"
    )
    assert_rejected_without_writes(store.root, message)


@pytest.mark.parametrize("row", ["trial", "branch"])
def test_v2_review_pending_blocks_otherwise_terminal_rows(timing, row):
    store, _ = timing
    store._append(
        {
            "kind": "synthetic-review-pending",
            "trial_id": next(iter(store.trials)),
            "request_id": next(iter(store.records)),
            f"{row}_patch": {"status": "failed", "review_pending": True},
        }
    )
    assert_rejected_without_writes(store.root, "not quiescent|pending")


@pytest.mark.parametrize(
    "damage", ["event", "source", "registration", "origin", "blob"]
)
def test_v2_native_hash_and_registration_checks_still_reject_damage(timing, damage):
    store, _ = timing
    message = "E journal is invalid"
    if damage == "event":
        event_path = next((store.root / "events").glob("*.json"))
        event = json.loads(event_path.read_bytes())
        event["synthetic"] = False
        event_path.write_bytes(_json_bytes(event))
    elif damage == "source":
        from pathlib import Path

        source = Path(next(iter(store.registration["source_files"])))
        source.write_bytes(source.read_bytes() + b"# drift\n")
        message = "frozen source file drift"
    elif damage == "registration":
        registration = dict(store.registration, replicate_count=4)
        (store.root / "registration.json").write_bytes(_json_bytes(registration))
        message = "requires reconciliation"
    elif damage == "origin":
        next((store.root / "events").glob("*.json")).unlink()
        message = "E journal origin is missing"
    else:
        digest = store._save("outputs", {"synthetic": True})
        store._append(
            {
                "kind": "synthetic-output",
                "request_id": next(iter(store.records)),
                "branch_patch": {"output_sha256": digest},
            }
        )
        (store.root / "outputs" / f"{digest}.json").write_bytes(b"{}")
        message = "immutable E artifact hash differs"
    refused = assert_rejected_without_writes(store.root, message)
    if damage == "registration":
        assert "timing registration differs" in str(refused.__cause__)


def test_nested_v2_journal_requires_its_own_registered_locks(timing):
    store, _ = timing
    parent = store.root.parent
    before = files(parent)
    with pytest.raises(PermissionError, match="journal root.*registered.*locked"):
        check_roots(parent)
    check_roots(parent, store.root)
    assert files(parent) == before
    assert not list(parent.rglob(".writer-lock"))
    assert not list(parent.rglob(".analysis36-campaign-lock"))


@pytest.mark.parametrize("name", [".writer-lock", ".analysis36-campaign-lock"])
def test_v2_existing_writer_locks_are_preserved(timing, name):
    store, _ = timing
    lock = store.root / name
    lock.mkdir()
    before = files(store.root)
    with pytest.raises(PermissionError, match="active|stale writer lock"):
        check_roots(store.root)
    assert lock.is_dir()
    assert files(store.root) == before
    other = ".analysis36-campaign-lock" if name == ".writer-lock" else ".writer-lock"
    assert not (store.root / other).exists()


@pytest.mark.parametrize("kind", ["timing-v1", "f8"])
def test_native_legacy_and_f8_journals_remain_accepted(tmp_path, kind):
    if kind == "timing-v1":
        from evals.tests.test_e_timing import setup
    else:
        from evals.tests.test_verification_v2 import setup

    _, store, *_ = setup.__wrapped__(tmp_path)
    before = files(store.root)
    check_roots(store.root)
    assert files(store.root) == before


def test_unknown_timing_registration_version_remains_rejected(timing):
    store, _ = timing
    registration = dict(
        store.registration, schema_version="task13-e-timing-registration-v3"
    )
    (store.root / "registration.json").write_bytes(_json_bytes(registration))
    refused = assert_rejected_without_writes(store.root, "requires reconciliation")
    assert "unrecognized controller registration" in str(refused.__cause__)
