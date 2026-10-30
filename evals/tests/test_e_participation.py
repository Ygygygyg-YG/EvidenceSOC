"""Explicit new anytime authority; old frozen inputs retain their review window."""

from copy import deepcopy
from datetime import UTC, datetime

import pytest

from evals.contracts import canonical_hash
from evals.e_planning import planning_requests, validate_e_planning_registration
from evals.tests.test_e_planning_contracts import registration_fixture
from evals.tests.test_e_timing import Clock
from evals.tests.test_e_timing_replicates import approved_source, registration
from evals.tests.test_e_trial_controller import chat_record
from evals.tests.test_e_trial_controller import host as _host_fixture

host = _host_fixture

POLICY = {
    "schema_version": "task13-e-participation-policy-v1",
    "dispatch_window": "anytime",
    "user_presence_required": False,
    "plan_approval": "individual-user-decision-v1",
    "authorization_record_sha256": "6" * 64,
}


def with_policy(planning):
    value = deepcopy(planning)
    value["core_config"]["participation_policy"] = deepcopy(POLICY)
    value["core_config_sha256"] = canonical_hash(value["core_config"])
    return validate_e_planning_registration(value)


def test_anytime_policy_is_carried_by_exact_registered_requests():
    legacy = registration_fixture()
    assert validate_e_planning_registration(legacy) == legacy
    assert all(
        "participation_policy" not in request.model_dump(mode="json")
        for request in planning_requests(legacy)
    )
    current = with_policy(legacy)
    assert canonical_hash(current) != canonical_hash(legacy)
    for request in planning_requests(current):
        assert request.participation_policy.model_dump(mode="json") == POLICY
        assert request.registration_sha256 == canonical_hash(current)
        assert request.plan_ttl_seconds == 1800
        assert request.auto_renew is False
        assert request.response_call_limit.model_dump() == {"logical": 1, "physical": 3}


@pytest.mark.parametrize(
    "field,value",
    [
        ("dispatch_window", "skip-all-approval"),
        ("user_presence_required", True),
        ("user_presence_required", 0),
        ("plan_approval", "scope-preapproves-plan"),
        ("authorization_record_sha256", "missing"),
        ("extra", "not-registered"),
    ],
)
def test_anytime_policy_rejects_unbound_or_weakened_approval_rules(field, value):
    planning = registration_fixture()
    planning["core_config"]["participation_policy"] = {**POLICY, field: value}
    planning["core_config_sha256"] = canonical_hash(planning["core_config"])
    with pytest.raises(ValueError):
        validate_e_planning_registration(planning)


@pytest.mark.parametrize("hour", [0, 4, 10, 16, 23])
def test_explicit_anytime_policy_allows_review_at_any_zoned_hour(hour):
    from evals.adapters.e_planning_review import require_review_window

    now = datetime(2026, 10, 30, hour, tzinfo=UTC)
    require_review_window(now, participation_policy=POLICY)


def test_anytime_policy_does_not_relax_timestamp_or_legacy_window_checks():
    from evals.adapters.e_planning_review import require_review_window

    with pytest.raises(PermissionError):
        require_review_window(datetime(2026, 10, 30, 4, tzinfo=UTC))
    with pytest.raises(PermissionError):
        require_review_window(
            datetime(2026, 10, 30, 4, tzinfo=UTC).replace(tzinfo=None),
            participation_policy=POLICY,
        )


def test_anytime_timing_packet_retains_individual_decision_and_pending_state(tmp_path):
    from evals.e_timing import ETimingCampaign, build_e_timing_registration

    original = registration(tmp_path)
    planning = with_policy(original["planning_registration"])
    dispatch = deepcopy(original["planning_dispatch_registration_receipt"])
    dispatch["registration_sha256"] = canonical_hash(planning)
    timing = build_e_timing_registration(
        planning,
        source_files=original["source_files"],
        f8_plan_sha256=original["f8_plan_sha256"],
        planning_dispatch_registration_receipt=dispatch,
    )
    clock = Clock()
    clock.utc = clock.utc.replace(hour=4)
    store = ETimingCampaign(timing, tmp_path / "anytime-store", now=clock.now)
    source = approved_source(store, 0, clock)
    original_source = deepcopy(source)
    packet = store.prepare_approval(timing["trials"][0]["trial_id"], source)
    assert packet["review_window"] == "anytime"
    assert packet["participation_policy"] == POLICY
    assert packet["reviewer"] == "user" and packet["decision"] is None
    assert source == original_source
    assert store.snapshot()["trials"][0]["status"] == "not_started"


@pytest.mark.asyncio
@pytest.mark.parametrize("host", [POLICY], indirect=True)
async def test_anytime_host_still_requires_each_actual_packet_decision(host):
    assert (await host.controller.plan(1))["status"] == "awaiting_approval"
    with pytest.raises(PermissionError):
        await host.controller.trial(1)
    packet = (await host.controller.read(1))["packet"]
    assert packet["review_window"] == "anytime"
    assert packet["participation_policy"] == POLICY
    wrong = chat_record(host, packet, packet_sha256="0" * 64)
    with pytest.raises(PermissionError):
        await host.controller.decision(
            1, packet_sha256=canonical_hash(packet), chat_record=wrong
        )
    actual = chat_record(host, packet)
    result = await host.controller.decision(
        1, packet_sha256=canonical_hash(packet), chat_record=actual
    )
    assert result["status"] == "approved"
    assert [row[0] for row in host.calls] == [
        "plan",
        "read_packet",
        "read_packet",
        "read_packet",
        "decision",
    ]


@pytest.mark.parametrize("host", [POLICY], indirect=True)
@pytest.mark.parametrize("missing", [True, False])
def test_anytime_host_requires_the_identical_new_scope_policy(host, missing):
    packet = host.controller._inputs["scope_packet"]
    if missing:
        packet.pop("participation_policy")
    else:
        packet["participation_policy"]["authorization_record_sha256"] = "7" * 64
    with pytest.raises(PermissionError, match="anytime policy"):
        host.controller._scope()


@pytest.mark.parametrize("host", [POLICY], indirect=True)
@pytest.mark.parametrize(
    "fault",
    ["missing", "digest", "authorization", "orphan", "orphan_digest", "no_policy"],
)
def test_host_recovery_scope_requires_the_same_lineage_and_authorization(host, fault):
    # The lineage schema/source checks run at registration. Exercise only the
    # host's independently pinned scope binding here, without a real recovery.
    lineage = {"authorization_record_sha256": POLICY["authorization_record_sha256"]}
    planning = host.controller._planning
    packet = host.controller._inputs["scope_packet"]
    planning["recovery_lineage"] = deepcopy(lineage)
    packet["recovery_lineage"] = deepcopy(lineage)
    packet["recovery_lineage_sha256"] = canonical_hash(lineage)
    if fault == "missing":
        packet.pop("recovery_lineage")
    elif fault == "digest":
        packet["recovery_lineage_sha256"] = "0" * 64
    elif fault == "authorization":
        lineage["authorization_record_sha256"] = "7" * 64
        planning["recovery_lineage"] = lineage
        packet["recovery_lineage"] = lineage
        packet["recovery_lineage_sha256"] = canonical_hash(lineage)
    elif fault.startswith("orphan"):
        planning.pop("recovery_lineage")
        if fault == "orphan_digest":
            packet.pop("recovery_lineage")
    else:
        host.controller._requests[0].participation_policy = None
    with pytest.raises(PermissionError, match="recovery"):
        host.controller._scope()


@pytest.mark.asyncio
async def test_anytime_review_runtime_wrapper_passes_the_bound_policy(
    tmp_path, monkeypatch
):
    from types import SimpleNamespace

    from evals.adapters import e_participation
    from evals.adapters.e_planning_review import build_review_request
    from evals.tests.test_e_planning_review import reference
    from scripts import task13_worker_runtime as runtime

    planning = planning_requests(with_policy(registration_fixture()))[0]
    request = build_review_request(
        planning, reference(planning), operation="read_packet"
    )
    midday = datetime(2026, 10, 30, 4, tzinfo=UTC)
    monkeypatch.setattr(
        e_participation, "datetime", SimpleNamespace(now=lambda tz: midday)
    )
    seen = []

    async def container(spec, agent_dir, options):
        seen.append(spec)
        return {"status": "completed", "model_ledger": []}

    monkeypatch.setattr(runtime, "run_container", container)
    assert (await runtime.run_e_planning_review_container(request, tmp_path, {}))[
        "status"
    ] == "completed"
    assert seen == [request.model_dump(mode="json")]


@pytest.mark.asyncio
async def test_anytime_review_runtime_inner_gate_reaches_normal_runtime_validation(
    tmp_path, monkeypatch
):
    from types import SimpleNamespace

    from evals.adapters import e_participation
    from evals.adapters.e_planning_review import build_review_request
    from evals.tests.test_e_planning_review import reference
    from scripts import task13_worker_runtime as runtime

    planning = planning_requests(with_policy(registration_fixture()))[0]
    request = build_review_request(
        planning, reference(planning), operation="read_packet"
    )
    midday = datetime(2026, 10, 30, 4, tzinfo=UTC)
    monkeypatch.setattr(
        e_participation, "datetime", SimpleNamespace(now=lambda tz: midday)
    )
    with pytest.raises(ValueError, match="host termination evidence is restricted"):
        await runtime.run_container(
            request.model_dump(mode="json"),
            tmp_path,
            {"host_termination_dir": str(tmp_path / "forbidden-review-option")},
        )
