"""Read-only pool controller/native evidence join; no execution or registration."""

from __future__ import annotations

import json
import sqlite3
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

from evals.contracts import canonical_hash

TTL_REASONS = frozenset(
    {
        "plan_expired",
        "trial_hard_deadline",
        "receipt_after_plan_expiry",
        "bootstrap_remaining_must_exceed_1500",
        "provisional_remaining",
        "remaining_changed_before_dispatch",
    }
)


def validate_attempt_inventory(
    order,
    begun,
    states,
    settlements,
    *,
    require_complete=True,
    policy=None,
    denied_trial_ids=(),
):
    from evals.timing_pool import (
        RECOVERY_REGISTRATION_SCHEMAS,
        REGISTRATION_SCHEMA,
        pool_policy,
    )

    selected = (
        pool_policy(REGISTRATION_SCHEMA)
        if policy is None
        else pool_policy(policy.registration_schema)
    )
    limit = selected.future_logical_limit
    if (
        len(order) != limit
        or len(set(order)) != limit
        or begun != order[: len(begun)]
        or len(begun) > limit
        or [s["trial_id"] for s in settlements] != begun
    ):
        raise PermissionError("all begun attempts must form one settled frozen prefix")
    if selected.registration_schema in RECOVERY_REGISTRATION_SCHEMAS:
        if (
            len(denied_trial_ids) != 6 - limit
            or len(set(denied_trial_ids)) != 6 - limit
            or set(denied_trial_ids) & set(order)
            or set(states) != set(order) | set(denied_trial_ids)
        ):
            raise PermissionError("exact excluded native slots required")
        for trial in denied_trial_ids:
            row = states[trial]
            if (
                not isinstance(row, dict)
                or row.get("status") != "not_started"
                or row.get("binding")
                or row.get("review_pending")
            ):
                raise PermissionError("denied native slot contains activity")
    qualified = []
    for trial_id, settlement in zip(begun, settlements, strict=True):
        if len(qualified) == 2:
            raise PermissionError("attempt after third qualified observation")
        row = states[trial_id]
        status = row if isinstance(row, str) else row["status"]
        if settlement["outcome"] == "qualified":
            if status != "completed":
                raise PermissionError("failed native trial cannot earn timing credit")
            qualified.append(trial_id)
        elif (
            settlement.get("evidence", {}).get("subtype") == "first_dispatch_ttl_guard"
        ):
            if settlement["outcome"] != "ttl_infrastructure_failure" or status not in {
                "not_started",
                "dispatched",
            }:
                raise PermissionError(
                    "host guard cannot relabel a native terminal or unknown outcome"
                )
        elif settlement.get("evidence", {}).get("subtype") == "pre_timing_expired":
            from evals.timing_pool_controller import validate_pre_timing_expiry_audit

            audit = settlement["evidence"]["audit"]
            if (
                settlement["outcome"] != "ttl_infrastructure_failure"
                or status != "not_started"
                or isinstance(row, str)
                or row.get("binding")
                or audit["trial_id"] != trial_id
            ):
                raise PermissionError(
                    "pre-timing expiry cannot rewrite a native started trial"
                )
            validate_pre_timing_expiry_audit(audit)
        elif (
            settlement["outcome"] != "ttl_infrastructure_failure"
            or isinstance(row, str)
            or status not in {"rejected", "failed", "expired"}
            or row.get("reason") not in TTL_REASONS
        ):
            raise PermissionError(
                "only independently settled recognized TTL failures may resume"
            )
    for trial_id in order[len(begun) :]:
        row = states[trial_id]
        if (row if isinstance(row, str) else row["status"]) != "not_started" or (
            isinstance(row, dict) and (row.get("binding") or row.get("review_pending"))
        ):
            raise PermissionError("unreported or later native attempt")
    if require_complete and len(qualified) != 2:
        raise PermissionError("exactly two new qualified observations required")
    return qualified


def _pin(ref):
    from evals.timing_pool import _json, _plain, file_sha256

    path = _plain(ref["path"])
    if file_sha256(path) != ref["sha256"]:
        raise PermissionError("controller raw evidence pin differs")
    return _json(path)


def _ledger(context, request, runtime):
    """Original registered identities plus every original settled SQL reservation."""
    from evals.adapters.budget_v2 import SupplementBudgetAccount

    ledger = runtime["model_ledger"]
    binding = request.budget_binding()
    if not 1 <= len(ledger) <= 3 or len({r["logical_call_id"] for r in ledger}) != 1:
        raise PermissionError("one bounded logical planning call required")
    account = SupplementBudgetAccount(
        context["budget_path"], **binding
    )  # bound-epoch constructor is SELECT-only
    hint = "v2-" + canonical_hash([request.slot_id, "respond", 1])
    logical = canonical_hash(["respond", "ResponseOutput", hint])
    result = []
    with sqlite3.connect(
        context["budget_path"].resolve().as_uri() + "?mode=ro", uri=True
    ) as db:
        db.execute("BEGIN")
        for index, call in enumerate(ledger, 1):
            if (
                call["physical_attempt"] != index
                or call["stable_logical_call_id"] != hint
                or call["role"] != "respond"
                or call["physical_request_id"]
                != account.physical_request_key(logical, index, explicit_call_id=hint)
                or any(call.get(k) != v for k, v in binding.items())
            ):
                raise PermissionError(
                    "planning physical attempt belongs to another native slot"
                )
            row = db.execute(
                "SELECT s.request_id,s.request_sha256,s.logical_call_id,s.physical_attempt,s.source_sha256,s.config_sha256,s.role,s.purpose,e.epoch_id,m.model_epoch_id,m.identity_manifest_sha256,r.actual,r.settled,s.requested_at,s.finished_at,s.duration_ms,s.usage_json FROM supplement_requests s JOIN reservations r ON r.id=s.reservation_id JOIN supplement_request_epochs e ON e.reservation_id=s.reservation_id JOIN supplement_request_models m ON m.reservation_id=s.reservation_id WHERE s.reservation_id=?",
                (call["reservation_id"],),
            ).fetchone()
            expected = (
                call["physical_request_id"],
                call["request_sha256"],
                call["logical_call_id"],
                index,
                request.source_sha256,
                request.config_sha256,
                "respond",
                "development",
                request.epoch_id,
                binding["model_epoch_id"],
                binding["model_identity_sha256"],
            )
            if (
                row is None
                or row[:11] != expected
                or row[12] != 1
                or row[11] is None
                or Decimal(str(row[11])) != Decimal(str(call["cost_cny"]))
            ):
                raise PermissionError(
                    "physical planning cost/identity is not independently settled"
                )
            if (
                row[13:16]
                != (call["requested_at"], call["finished_at"], call["duration_ms"])
                or json.loads(row[16]) != call["usage"]
            ):
                raise PermissionError("actual request timing/usage ledger differs")
            received = call.get("raw_response")
            model = context["model"]["expected_model"]
            if (call.get("http_status") == 200 or isinstance(received, dict)) and (
                not isinstance(received, dict)
                or received.get("model") != model["response_model"]
                or received.get("system_fingerprint") != model["fingerprint"]
                or call.get("response_model") != model["response_model"]
                or call.get("system_fingerprint") != model["fingerprint"]
            ):
                raise PermissionError("actual received model identity differs")
            result.append(
                {
                    "reservation_id": call["reservation_id"],
                    "request_id": call["physical_request_id"],
                    "actual": Decimal(str(row[11])),
                    "requested_at": row[13],
                    "finished_at": row[14],
                }
            )
    return result


def _quiescence(proof, contexts):
    from hashlib import sha256

    from evals.timing_pool import _json, _plain, _time, file_sha256

    when = _time(proof["inspected_at"])
    expected = {}
    for context in contexts.values():
        for path in context["reader"]._termination.glob("*/*.json"):
            value = _json(_plain(path))
            if _time(value["recorded_at"]) > when:
                continue
            digest = file_sha256(path)
            if (
                value["status"] != "verified"
                or value["host_process_exited"] is not True
                or value["container_absent"] is not True
            ):
                raise PermissionError("unknown native lifecycle at recovery boundary")
            expected[digest] = value
    supplied = {r["receipt_sha256"]: r["inspection"] for r in proof["proofs"]}
    if len(supplied) != len(proof["proofs"]) or set(supplied) != set(expected):
        raise PermissionError("free guard must cover every then-owned worker")
    for digest, record in supplied.items():
        container = expected[digest]["container_id"]
        if record != {
            "argv": [
                "docker",
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                "id=" + container,
                "--format",
                "{{.ID}}",
            ],
            "returncode": 0,
            "stdout_sha256": sha256(b"").hexdigest(),
            "stderr_sha256": sha256(b"").hexdigest(),
        }:
            raise PermissionError(
                "fresh recovery guard does not establish container absence"
            )
    from evals.timing_pool import (
        RECOVERY_REGISTRATION_SCHEMAS,
        validate_recovery_quarantine,
    )

    pools = [
        getattr(c["reader"], "_inputs", {}).get("pool_authority", {})
        for c in contexts.values()
    ]
    recovery = [
        p for p in pools if p.get("schema_version") in RECOVERY_REGISTRATION_SCHEMAS
    ]
    if recovery:
        pool = recovery[0]
        if any(p != pool for p in pools):
            raise PermissionError("quarantine parent pool differs across contexts")
        quarantine = validate_recovery_quarantine(pool)
        absence = proof.get("quarantined_predecessor_workers")
        expected_workers = []
        for worker in quarantine["workers"]:
            container = worker["container_id"]
            expected_workers.append(
                {
                    "container_id": container,
                    "inspection": {
                        "argv": [
                            "docker",
                            "container",
                            "ls",
                            "--all",
                            "--no-trunc",
                            "--filter",
                            "id=" + container,
                            "--format",
                            "{{.ID}}",
                        ],
                        "returncode": 0,
                        "stdout_sha256": sha256(b"").hexdigest(),
                        "stderr_sha256": sha256(b"").hexdigest(),
                    },
                }
            )
        if absence != {
            "schema_version": "task13-manual-quarantine-worker-absence-v1",
            "status": "verified",
            "workers": expected_workers,
        }:
            raise PermissionError("fresh quarantine predecessor worker absence differs")
    return when


def validate_controller_evidence(evidence, pool, original, *, require_complete=True):
    from evals.adapters.verification_worker import VerificationWorkerRequest
    from evals.e_planning import planning_requests
    from evals.timing_pool import (
        RECOVERY_REGISTRATION_SCHEMA,
        RECOVERY_REGISTRATION_SCHEMAS,
        REGISTRATION_SCHEMA,
        STARTUP_RECOVERY_REGISTRATION_SCHEMA,
        _branches,
        _json,
        _plain,
        _time,
        _validate_host_semantics,
        _view,
        pool_policy,
        validate_denied_native_slot,
        validate_migration_marker,
    )
    from evals.timing_pool_controller import validate_pool_journal_evidence
    from evals.verification_v2 import _validated_worker_result
    from scripts.task13_timing_pool import NativePoolController

    selected = pool_policy(pool)
    manifest = _pin(evidence["pool_host_manifest"])
    host_schema = {
        REGISTRATION_SCHEMA: "task13-e-timing-pool-host-v1",
        RECOVERY_REGISTRATION_SCHEMA: "task13-e-timing-pool-host-v2",
        STARTUP_RECOVERY_REGISTRATION_SCHEMA: "task13-e-timing-pool-host-v3",
    }[selected.registration_schema]
    if (
        manifest["schema_version"] != host_schema
        or _pin(manifest["pool_registration"]) != pool
        or manifest["hosts"] != evidence["host_manifests"]
        or manifest["journal_path"] != evidence["pool_journal"]["path"]
        or manifest["journal_path"] != pool["execution_journal_path"]
        or manifest["migration_marker"] != evidence["migration_marker"]
        or manifest["original_account_baseline"] != pool["original_account_baseline"]
    ):
        raise PermissionError("actual pool host manifest differs")
    _plain(evidence["pool_journal"]["path"])
    if (
        selected.registration_schema in RECOVERY_REGISTRATION_SCHEMAS
        and manifest["migration_marker"] != pool["quarantine_record"]
    ):
        raise PermissionError("pool host quarantine raw reference differs")
    transcript = validate_pool_journal_evidence(evidence, pool)
    state = transcript["state"]
    events = transcript["events"]
    if (
        state["pending"]
        or state["stopped"]
        or (require_complete and state["qualified"] != 3)
    ):
        raise PermissionError("pool has not completed exact settled target")
    contexts = {}
    views = {}
    states = {}
    requests = {}
    parents = []
    decisions = []
    for child in pool["children"]:
        host = _pin(evidence["host_manifests"][child["child_id"]])
        inputs = {k: _pin(v) for k, v in host["inputs"].items()}
        if (
            inputs.get("pool_authority") != pool
            or inputs["timing_registration"] != child["registration"]
            or Path(host["output_dir"]) / "timing" != Path(child["evidence_root"])
        ):
            raise PermissionError(
                "native child host is not exact authorized pool member"
            )
        root = Path(child["evidence_root"])
        if (root / "registration.json").exists():
            view = _view(root)
            if view.registration != child["registration"]:
                raise PermissionError("child native registration differs")
        else:
            if root.exists() and any(root.rglob("*")):
                raise PermissionError("unregistered child evidence exists")
            view = SimpleNamespace(root=root, registration=child["registration"])
            view.trials = {
                t["trial_id"]: {
                    "trial_id": t["trial_id"],
                    "status": "not_started",
                    "binding": None,
                }
                for t in child["registration"]["trials"]
            }
            view.records = {}
        context = _validate_host_semantics(view, host, inputs)
        context["reader"]._manifest_pin = evidence["host_manifests"][child["child_id"]]
        contexts[child["child_id"]] = context
        views[child["child_id"]] = view
        states.update(view.trials)
        requests.update(
            {
                r.trial_id: r
                for r in planning_requests(
                    child["registration"]["planning_registration"]
                )
            }
        )
        parents.append(host["inputs"]["scope_packet"])
        decisions.append(host["inputs"]["scope_decision"])
    if (
        parents != evidence["parent_scope_packets"]
        or decisions != evidence["parent_scope_decisions"]
        or len({p["sha256"] for p in parents}) != 1
        or len({p["sha256"] for p in decisions}) != 1
    ):
        raise PermissionError(
            "all children require one original parent scope and actual decision"
        )
    validate_migration_marker(
        _pin(evidence["migration_marker"]), pool, parents[0], decisions[0]
    )
    begun = [e["payload"]["trial_id"] for e in events if e["kind"] == "begin"]
    order = [a["trial_id"] for a in pool["attempt_order"]]
    qualified = validate_attempt_inventory(
        order,
        begun,
        states,
        transcript["settlements"],
        require_complete=require_complete,
        policy=selected,
        denied_trial_ids=[a["trial_id"] for a in pool.get("denied_attempts", [])],
    )
    for denied in pool.get("denied_attempts", []):
        validate_denied_native_slot(
            contexts[denied["child_id"]],
            requests[denied["trial_id"]],
            views[denied["child_id"]],
        )
    by_attempt = {a["trial_id"]: a for a in pool["attempt_order"]}
    settlements = {p["trial_id"]: p for p in transcript["settlements"]}
    expired = {
        trial_id
        for trial_id, p in settlements.items()
        if p.get("evidence", {}).get("subtype") == "pre_timing_expired"
    }
    guarded = {
        trial_id
        for trial_id, p in settlements.items()
        if p.get("evidence", {}).get("subtype") == "first_dispatch_ttl_guard"
    }
    resources, seen = set(), set()
    old = _view(pool["imported_observations"][0]["evidence_root"])
    _branches(old, original, resources, seen)
    old_source = old._blob("sources", original["binding"]["source_sha256"])["resources"]
    resources.update(
        ({"database_name": "database", "index_name": "index"}.get(k, k), old_source[k])
        for k in (
            "database_name",
            "index_name",
            "incident_id",
            "run_id",
            "planning_slot_id",
        )
    )
    prior_maximum = max(
        (
            _time(original["completed_at"]) - _time(original["started_at"])
        ).total_seconds(),
        (original["completed_monotonic_ns"] - original["started_monotonic_ns"]) / 1e9,
    )
    total_rows = []
    costs = {}
    terminals = {}
    rows_by_trial = {}
    for trial_id in order:
        child_id = by_attempt[trial_id]["child_id"]
        context = contexts[child_id]
        view = views[child_id]
        request = requests[trial_id]
        claim = context["claims"][trial_id]
        slot = context["reader"]._root / "slots" / request.planning_slot_id
        if trial_id not in begun:
            if claim["status"] != "unclaimed" or slot.exists() and any(slot.iterdir()):
                raise PermissionError("later native work omitted from pool transcript")
            continue
        if claim["status"] != "started":
            raise PermissionError("pool begin lacks original native planning claim")
        terminal = _json(slot / "plan-terminal.json")
        started = _json(slot / "plan-started.json")
        if (
            terminal["start_sha256"] != canonical_hash(started)
            or started["request"] != request.model_dump(mode="json")
            or started["request_sha256"] != canonical_hash(request)
        ):
            raise PermissionError("native planning origin differs")
        runtime = _pin(terminal["runtime_result"])
        from evals.timing_pool import _validate_runtime_capture

        _validate_runtime_capture(
            runtime, terminal, context["reader"]._inputs["runtime_options"], request
        )
        rows = _ledger(context, request, runtime)
        rows_by_trial[trial_id] = rows
        for key, value in (
            ("container", runtime["isolation_evidence"]["container"]["container_id"]),
            ("worker", runtime["isolation_evidence"]["probe"]["nonce"]),
        ):
            if (key, value) in resources:
                raise PermissionError("planning worker resources were reused")
            resources.add((key, value))
        total_rows.extend(rows)
        costs[trial_id] = sum((r["actual"] for r in rows), Decimal(0))
        terminals[(trial_id, "plan")] = terminal
        retained = _pin(terminal["resources"])
        for key in (
            "database_name",
            "index_name",
            "incident_id",
            "run_id",
            "planning_slot_id",
        ):
            identity = (
                {"database_name": "database", "index_name": "index"}.get(key, key),
                retained[key],
            )
            if identity in resources:
                raise PermissionError("attempts reused original retained resources")
            resources.add(identity)
        if terminal["status"] != "awaiting_approval":
            raise PermissionError("unqualified planning outcome must STOP")
        for phase in ("decision", "trial"):
            path = slot / (phase + "-terminal.json")
            if path.exists():
                terminals[(trial_id, phase)] = _json(path)
        from evals.adapters.e_planning_review import (
            build_review_request,
            validate_review_state,
        )
        from evals.adapters.e_planning_worker import _claim_binding
        from evals.timing_pool import (
            _archive_context,
            _validate_approval_semantics,
            _validate_source_semantics,
        )

        if trial_id in expired:
            _validate_pre_timing_expiry_semantics(
                context,
                request,
                view,
                terminal,
                settlements[trial_id],
                rows,
                events,
                contexts,
            )
            continue
        decision = terminals[(trial_id, "decision")]
        decided = _pin(decision["runtime_result"])
        chat = _pin(decision["chat_record"])
        pending = _pin(terminal["retained_state"])
        source = context["reader"]._source(
            request, decided["source"]["state"], pending, retained
        )
        _validate_source_semantics(view, view.trials[trial_id], source)
        review = build_review_request(request, retained, operation="read_packet")
        validate_review_state(
            review, source["state"], context["imported"], _claim_binding(request, claim)
        )
        before = next(
            e["payload"]["quiescence"]["inspected_at"]
            for e in events
            if e["kind"] == "phase_claim"
            and e["payload"]["trial_id"] == trial_id
            and e["payload"]["phase"] == "trial"
        )
        _validate_approval_semantics(
            context,
            view.trials[trial_id],
            source,
            chat,
            _json(slot / "decision-started.json"),
            decided,
            _archive_context({}),
            approved_before=before,
        )
        if trial_id in guarded:
            validate_first_dispatch_guard_evidence(
                context, request, view, source, settlements[trial_id], prior_maximum
            )
        validate_dispatch_boundary(
            view,
            trial_id,
            source["state"],
            prior_maximum,
            qualified=trial_id in qualified,
        )
        # Include every emitted worker resource, even in failed/expired attempts.
        if trial_id in qualified:
            _branches(view, view.trials[trial_id], resources, seen)
            trial = view.trials[trial_id]
            prior_maximum = max(
                prior_maximum,
                (
                    _time(trial["completed_at"]) - _time(trial["started_at"])
                ).total_seconds(),
                (trial["completed_monotonic_ns"] - trial["started_monotonic_ns"]) / 1e9,
            )
        else:
            for row in view.records.values():
                if row["trial_id"] == trial_id and row.get("output_sha256"):
                    raw = view._blob("inputs", row["input_sha256"])
                    result = view._blob("outputs", row["output_sha256"])
                    _validated_worker_result(
                        result,
                        VerificationWorkerRequest.model_validate(raw),
                        view.identity,
                        resources,
                    )
        for row in view.records.values():
            if row["trial_id"] == trial_id and row.get("input_sha256"):
                raw = view._blob("inputs", row["input_sha256"])
                from evals.worker_lifecycle import HostWorkerLifecycleVerifier

                verifier = HostWorkerLifecycleVerifier(context["reader"]._termination)
                if (
                    verifier(raw, timed_out=row["status"] != "completed")["status"]
                    != "verified"
                ):
                    raise PermissionError("begun worker lacks native termination")
    if len(total_rows) > selected.future_physical_limit or len(
        {r["reservation_id"] for r in total_rows}
    ) != len(total_rows):
        raise PermissionError("pool physical cap or unique reservation violated")
    budgets = {str(c["budget_path"]) for c in contexts.values()}
    if len(budgets) != 1:
        raise PermissionError("pool split original budget accounts")
    budget = Path(next(iter(budgets)))
    epochs = {r.epoch_id for r in requests.values()}
    with sqlite3.connect(budget.resolve().as_uri() + "?mode=ro", uri=True) as db:
        actual = db.execute(
            "SELECT s.reservation_id FROM supplement_requests s JOIN supplement_request_epochs e ON e.reservation_id=s.reservation_id WHERE e.epoch_id IN ("
            + ",".join("?" for _ in epochs)
            + ") AND s.purpose=?",
            (*sorted(epochs), "development"),
        ).fetchall()
    if {r[0] for r in actual} != {r["reservation_id"] for r in total_rows}:
        raise PermissionError(
            "native epoch contains unreported physical development attempts"
        )
    checker = object.__new__(NativePoolController)
    checker.budget_path = budget
    checker.manifest = manifest
    total_spent = checker.budget()
    if Decimal(str(state["spent_yuan"])) != total_spent or total_spent > 6:
        raise PermissionError("pool final spend differs from original settled account")
    if Decimal(str(events[0]["payload"]["initial_spent_yuan"])) != total_spent - sum(
        costs.values(), Decimal(0)
    ):
        raise PermissionError("pool imported historical cost baseline differs")
    settlements = {p["trial_id"]: p for p in transcript["settlements"]}
    for trial_id, p in settlements.items():
        if Decimal(str(p["actual_yuan"])) != costs[trial_id]:
            raise PermissionError("settled trial cost differs from native ledger")
        native = p["evidence"].get("native")
        state_row = states[trial_id]
        if p["outcome"] == "qualified":
            if native["trial_id"] != trial_id or native[
                "registration_sha256"
            ] != canonical_hash(views[by_attempt[trial_id]["child_id"]].registration):
                raise PermissionError("qualified settlement native identity differs")
        elif (
            trial_id not in expired and trial_id not in guarded and native != state_row
        ):
            raise PermissionError(
                "TTL settlement does not retain exact native terminal"
            )
        when = _quiescence(p["evidence"]["quiescence"], contexts)
        if any(_time(r["finished_at"]) > when for r in rows_by_trial[trial_id]):
            raise PermissionError("settlement precedes actual model completion")
        if (
            p["outcome"] == "ttl_infrastructure_failure"
            and p["observed_max_seconds"] != 0
        ):
            raise PermissionError("failed attempt acquired timing maximum credit")
    spent_before = {}
    reserved_by_trial = {}
    running_spent = Decimal(str(events[0]["payload"]["initial_spent_yuan"]))
    begin_times = {}
    begin_reviews = {}
    for event in events:
        payload = event["payload"]
        if event["kind"] == "begin":
            trial = payload["trial_id"]
            spent_before[trial] = running_spent
            reserved_by_trial[trial] = Decimal(str(payload["reserved_yuan"]))
            begin_times[trial] = _time(payload["started_at"])
            begin_reviews[trial] = payload.get("guard_review_sha256")
        elif event["kind"] in {"settle", "expiry_audit"}:
            running_spent += Decimal(str(payload["actual_yuan"]))
    last_boundary = None
    for event in events:
        p = event["payload"]
        if event["kind"] in {"settle", "expiry_audit"}:
            last_boundary = _time(p["evidence"]["quiescence"]["inspected_at"])
        elif event["kind"] == "begin":
            if last_boundary is not None and _time(p["started_at"]) < last_boundary:
                raise PermissionError("new attempt precedes settled recovery guard")
            from scripts.task13_timing_pool import derive_next_three_bound

            context = contexts[by_attempt[p["trial_id"]]["child_id"]]
            if Decimal(str(p["reserved_yuan"])) != derive_next_three_bound(
                context["reader"]
            ):
                raise PermissionError(
                    "begin reservation differs from native worst-case three-call bound"
                )
            if any(
                _time(r["requested_at"]) < _time(p["started_at"])
                for r in rows_by_trial[p["trial_id"]]
            ):
                raise PermissionError("native call preceded pool begin authority")
        elif event["kind"] == "resume":
            current = _quiescence(p["guard_evidence"], contexts)
            if last_boundary is None or current < last_boundary:
                raise PermissionError("TTL resume reused stale free guard")
            last_boundary = current
        elif event["kind"] == "phase_claim":
            if p["child_id"] != by_attempt[p["trial_id"]]["child_id"]:
                raise PermissionError("phase claim belongs to another native child")
            current = _quiescence(p["quiescence"], contexts)
            if last_boundary is not None and current < last_boundary:
                raise PermissionError("native phase used stale guard evidence")
            last_boundary = current
            if p["phase"] == "plan":
                context = contexts[by_attempt[p["trial_id"]]["child_id"]]
                validate_phase_free_admission(
                    p["free_admission"],
                    pool=pool,
                    host=context["reader"],
                    request=requests[p["trial_id"]],
                    now=begin_times[p["trial_id"]],
                    guard_review_sha256=begin_reviews[p["trial_id"]],
                    spent=spent_before[p["trial_id"]],
                    reserve=reserved_by_trial[p["trial_id"]],
                )
            if p["phase"] == "decision":
                record = _pin(p["chat_record"])
                native = _pin(terminals[(p["trial_id"], "decision")]["chat_record"])
                if record != native or p["packet_sha256"] != record["packet_sha256"]:
                    raise PermissionError(
                        "controller decision differs from actual original chat"
                    )
        elif event["kind"] == "phase_finish" and p["phase"] in {"plan", "decision"}:
            if p["result_sha256"] != canonical_hash(
                terminals[(p["trial_id"], p["phase"])]
            ):
                raise PermissionError(
                    "controller phase finish differs from native terminal"
                )
        elif event["kind"] == "phase_finish" and p["phase"] == "trial":
            view = views[by_attempt[p["trial_id"]]["child_id"]]
            if p["trial_id"] in guarded:
                expected = {
                    "status": "ttl_guard_rejected",
                    "trial_id": p["trial_id"],
                    "guard_receipt": settlements[p["trial_id"]]["evidence"][
                        "guard_receipt"
                    ],
                }
                if p["result_sha256"] != canonical_hash(expected):
                    raise PermissionError(
                        "host guard phase differs from exact typed receipt"
                    )
            elif not _native_progress_matches(view, p["trial_id"], p["result_sha256"]):
                raise PermissionError(
                    "controller trial finish differs from original native journal prefix"
                )
        elif event["kind"] == "phase_finish" and p["phase"] == "read":
            context = contexts[by_attempt[p["trial_id"]]["child_id"]]
            if not _native_read_matches(
                context, requests[p["trial_id"]], p["result_sha256"]
            ):
                raise PermissionError(
                    "controller read finish differs from actual zero-model host read"
                )
    validate_native_guard_reviews(events, pool)
    return {
        "qualified_trial_ids": qualified,
        "contexts": contexts,
        "views": views,
        "transcript": transcript,
    }


def validate_phase_free_admission(recorded, **kwargs):
    """Replay a native gate's raw pin and authenticate its recorded derived time."""
    from scripts.task13_timing_pool import require_free_admission

    if not isinstance(recorded, dict) or set(recorded) != {
        "path",
        "sha256",
        "checked_at",
    }:
        raise PermissionError("invalid recorded free admission proof")
    actual = require_free_admission(
        {key: recorded[key] for key in ("path", "sha256")}, **kwargs
    )
    if actual != recorded:
        raise PermissionError("recorded free admission differs from original raw gate")


def validate_dispatch_boundary(
    view, trial_id, approved_state, prior_maximum, *, qualified
):
    """Recheck the real first dispatch against the previously settled pool M."""
    from evals.timing_pool import _time
    from evals.timing_pool_controller import DEADLINE

    dispatched = [
        _time(row["dispatched_at"])
        for row in view.records.values()
        if row["trial_id"] == trial_id and row.get("dispatched_at")
    ]
    if not dispatched:
        if qualified:
            raise PermissionError("qualified trial lacks actual dispatch")
        return
    first = min(dispatched)
    if first >= DEADLINE:
        raise PermissionError("actual first dispatch violates engineering deadline")
    remaining = (
        _time(approved_state["response_plan"]["expires_at"]) - first
    ).total_seconds()
    if qualified and remaining <= max(1500, 1.5 * prior_maximum + 300):
        raise PermissionError("actual first dispatch violates shared timing margin")


def _native_progresses(view):
    from copy import deepcopy

    from evals.e_timing import ETimingCampaign

    replay = object.__new__(ETimingCampaign)
    replay.registration = deepcopy(view.registration)
    replay.identity = deepcopy(view.identity)
    replay.trials = {
        t["trial_id"]: {
            "trial_id": t["trial_id"],
            "source_row_id": t["source_row_id"],
            "status": "not_started",
            "reason": None,
            "binding": None,
        }
        for t in view.registration["trials"]
    }
    replay.records = {
        b["request_id"]: {
            **deepcopy(b),
            "trial_id": t["trial_id"],
            "status": "not_started",
            "reason": None,
        }
        for t in view.registration["trials"]
        for b in t["branches"]
    }
    for event in view.events:
        replay._apply(event["payload"])
        yield canonical_hash(event), replay._progress()


def _native_progress_matches(view, trial_id, expected):
    for _, progress in _native_progresses(view):
        trial = next(t for t in progress["trials"] if t["trial_id"] == trial_id)
        if (
            trial["status"] in {"completed", "rejected", "failed", "expired"}
            and canonical_hash(progress) == expected
        ):
            return True
    return False


def native_snapshot_matches(view, current, stored):
    omitted = {"journal_head_sha256", "journal_trials"}
    if {k: v for k, v in current.items() if k not in omitted} != {
        k: v for k, v in stored.items() if k not in omitted
    }:
        return False
    return any(
        head == stored["journal_head_sha256"]
        and progress["trials"] == stored["journal_trials"]
        and any(
            t["trial_id"] == stored["trial_id"] and t["status"] == "completed"
            for t in progress["trials"]
        )
        for head, progress in _native_progresses(view)
    )


def _native_host_read_receipt_path(root, receipt):
    from hashlib import sha256

    from scripts.task13_e_trial import _bytes

    digest = sha256(_bytes(receipt)).hexdigest()
    path = root / "artifacts/host-review-read" / digest
    if _pin({"path": str(path), "sha256": digest}) != receipt:
        raise PermissionError("host read receipt closure differs")
    return path


def _native_read_matches(context, request, expected):
    from evals.adapters.e_planning_review import build_review_request
    from evals.timing_pool import _json, _plain, file_sha256

    root = context["reader"]._root
    resources = _pin(
        _json(root / "slots" / request.planning_slot_id / "plan-terminal.json")[
            "resources"
        ]
    )
    review = build_review_request(request, resources, operation="read_packet")
    for path in (root / "artifacts/host-review-result").glob("*"):
        value = _json(_plain(path))
        digest = file_sha256(path)
        if path.name != digest:
            raise PermissionError("host read raw artifact differs")
        if value.get("input_sha256") != canonical_hash(review):
            continue
        receipt = value.get("host_read_receipt", {})
        if (
            value.get("status") != "completed"
            or value.get("model_ledger") != []
            or "isolation_evidence" in value
            or receipt.get("schema_version") != "task13-e-host-review-read-v1"
            or receipt.get("origin") != "host_original_postgresql_read"
            or receipt.get("request_sha256") != canonical_hash(review)
            or receipt.get("state_sha256") != value.get("source_state_sha256")
            or canonical_hash(value["source"]["state"]) != value["source_state_sha256"]
        ):
            raise PermissionError("native original product host read semantics differ")
        receipt_path = _native_host_read_receipt_path(root, receipt)
        result = {
            "status": "read",
            "packet": value["approval_packet"],
            "packet_sha256": canonical_hash(value["approval_packet"]),
            "host_read_result": {"path": str(path), "sha256": digest},
            "host_read_receipt": {
                "path": str(receipt_path),
                "sha256": file_sha256(receipt_path),
            },
        }
        if canonical_hash(result) == expected:
            return True
    return False


def _validate_pre_timing_expiry_semantics(
    context, request, view, terminal, settlement, rows, events, contexts
):
    """Join expiry to original retained artifacts, original SQL and actual host read."""
    from evals.adapters.e_planning_review import (
        build_review_request,
        validate_review_state,
    )
    from evals.adapters.e_planning_worker import _claim_binding
    from evals.e_timing import _validate_replicate_source
    from evals.timing_pool import _plain, _time
    from evals.timing_pool_controller import validate_pre_timing_expiry_audit

    proof = settlement["evidence"]
    audit = proof["audit"]
    validate_pre_timing_expiry_audit(audit)
    reader = context["reader"]
    slot = reader._root / "slots" / request.planning_slot_id
    pending = _pin(terminal["retained_state"])
    resources = _pin(terminal["resources"])
    if (
        audit["retained_state"] != pending
        or audit["resources"] != resources
        or audit["request_sha256"] != canonical_hash(request)
    ):
        raise PermissionError(
            "expiry differs from original request and retained native artifacts"
        )
    review = build_review_request(request, resources, operation="read_packet")
    live = _pin(audit["host_review_result_pin"])
    receipt = _pin(audit["host_read_receipt_pin"])
    if (
        audit["review_request"] != review.model_dump(mode="json")
        or live != audit["host_review_result"]
        or receipt != live["host_read_receipt"]
        or receipt["resources_sha256"] != canonical_hash(review.case_resource)
    ):
        raise PermissionError("expiry original host read closure differs")
    expected_root = reader._root / "artifacts"
    for key, category in [
        ("host_review_result_pin", "host-review-result"),
        ("host_read_receipt_pin", "host-review-read"),
    ]:
        pin = audit[key]
        if _plain(pin["path"]) != expected_root / category / pin["sha256"]:
            raise PermissionError("expiry read outside original native host artifacts")
    read_result = {
        "status": "read",
        "packet": live["approval_packet"],
        "packet_sha256": canonical_hash(live["approval_packet"]),
        "host_read_result": audit["host_review_result_pin"],
        "host_read_receipt": audit["host_read_receipt_pin"],
    }
    if not _native_read_matches(context, request, canonical_hash(read_result)):
        raise PermissionError(
            "expiry is not an original native SQL-backed readonly read"
        )
    source = reader._source(request, live["source"]["state"], pending, resources)
    registered = next(
        t for t in view.registration["trials"] if t["trial_id"] == request.trial_id
    )
    _validate_replicate_source(view.registration, registered, source)
    validate_review_state(
        review,
        source["state"],
        context["imported"],
        _claim_binding(request, context["claims"][request.trial_id]),
    )
    expected_resources = {
        k: resources[k]
        for k in ("database_name", "index_name", "incident_id", "source_commit")
    }
    if live["source"]["resources"] != expected_resources:
        raise PermissionError("expiry actual resources differ")
    stored = audit["native_snapshot"]
    if stored.get("journal_exists") is False:
        expected = {
            "journal_exists": False,
            "registration_sha256": canonical_hash(view.registration),
            "trials": [
                {"trial_id": t["trial_id"], "status": "not_started", "binding": None}
                for t in view.registration["trials"]
            ],
            "records": [],
        }
        if stored != expected or any(
            view.trials[t["trial_id"]]["status"] != "not_started"
            for t in view.registration["trials"][: request.ordinal - 1]
        ):
            raise PermissionError(
                "expiry claimed missing native journal after earlier native work"
            )
    elif not any(progress == stored for _, progress in _native_progresses(view)):
        raise PermissionError(
            "expiry native snapshot is not an immutable native prefix"
        )
    if view.trials[request.trial_id]["status"] != "not_started" or view.trials[
        request.trial_id
    ].get("binding"):
        raise PermissionError("externally audited expiry later reused its native trial")
    if any(
        r["trial_id"] == request.trial_id
        and (r["status"] != "not_started" or r.get("input_sha256"))
        for r in view.records.values()
    ):
        raise PermissionError("pre-timing expiry has actual native dispatch")
    started_path = slot / "decision-started.json"
    terminal_path = slot / "decision-terminal.json"
    if started_path.exists() or terminal_path.exists():
        raise PermissionError(
            "attempted or unknown native decision cannot become pre-timing expiry"
        )
    required = {
        e["payload"]["chat_record"]["sha256"]
        for e in events
        if e["kind"] == "phase_claim"
        and e["payload"]["trial_id"] == request.trial_id
        and e["payload"].get("chat_record")
    }
    actual = set()
    for item in audit["decision_records"]:
        record = _pin(item["pin"])
        actual.add(item["pin"]["sha256"])
        reader._chat(
            record, kind="plan", participation_policy=request.participation_policy
        )
        if (
            record != item["record"]
            or record.get("decision") != "approved"
            or record.get("case_id") != request.case_id
            or record.get("incident_id") != request.incident_id
            or _time(record["decided_at"]) > _time(audit["checked_at"])
        ):
            raise PermissionError("expiry rejected or misbound actual user reply")
    if not required.issubset(actual):
        raise PermissionError("expiry omitted original actual user decision")
    given = {r["reservation_id"]: r for r in audit["planning_ledger_rows"]}
    if len(given) != len(audit["planning_ledger_rows"]) or set(given) != {
        r["reservation_id"] for r in rows
    }:
        raise PermissionError("expiry omits native planning charges")
    for row in rows:
        item = given[row["reservation_id"]]
        if (
            item["settled"] != 1
            or Decimal(str(item["actual"])) != row["actual"]
            or Decimal(str(item["expected_cost"])) != row["actual"]
            or item["physical_request_id"] != row["request_id"]
        ):
            raise PermissionError("expiry fee differs from original settled SQL row")
    quiet = _quiescence(proof["quiescence"], contexts)
    if (
        not _time(receipt["started_at"])
        <= _time(receipt["finished_at"])
        <= quiet
        <= _time(audit["checked_at"])
    ):
        raise PermissionError("expiry actual read/cleanup ordering differs")
    if (
        _time(audit["checked_at"]) - _time(receipt["finished_at"])
    ).total_seconds() > 300:
        raise PermissionError("expiry reused stale actual product read")


def guard_observations(pool, qualified_ids):
    from evals.timing_pool import read_native_observation

    refs = list(pool["imported_observations"])
    for trial_id in qualified_ids:
        child = next(
            c
            for c in pool["children"]
            if any(t["trial_id"] == trial_id for t in c["registration"]["trials"])
        )
        refs.append(
            {
                "evidence_root": child["evidence_root"],
                "trial_id": trial_id,
                "registration_sha256": canonical_hash(child["registration"]),
            }
        )
    result = []
    for ref in refs:
        observed = read_native_observation(
            ref["evidence_root"],
            ref["trial_id"],
            evidence_archives=pool.get("evidence_archives"),
        )
        if observed["registration_sha256"] != ref["registration_sha256"]:
            raise PermissionError("guard review native registration changed")
        head = observed.pop("journal_head_sha256")
        observed.pop("journal_trials")
        result.append(
            {
                "trial_id": ref["trial_id"],
                "reference": ref,
                "observation": observed,
                "native_journal_head_sha256": head,
                "duration_wall_seconds": observed["duration_wall_seconds"],
                "duration_monotonic_seconds": observed["duration_monotonic_seconds"],
            }
        )
    return result


def validate_native_guard_reviews(events, pool):
    from evals.timing_pool import _time, _view

    qualified = []
    for event in events:
        p = event["payload"]
        if event["kind"] == "settle" and p["outcome"] == "qualified":
            qualified.append(p["trial_id"])
        if event["kind"] != "guard_review":
            continue
        actual = guard_observations(pool, qualified)
        if len(actual) != len(p["observations"]):
            raise PermissionError("guard review omitted qualified observation")
        for expected, supplied in zip(actual, p["observations"], strict=True):
            head = supplied["native_journal_head_sha256"]
            expected["native_journal_head_sha256"] = head
            if _time(supplied["observation"]["completed_at"]) > _time(p["checked_at"]):
                raise PermissionError("guard review predates native completion")
            view = _view(supplied["reference"]["evidence_root"])
            if expected != supplied or not _completed_native_prefix(
                view, supplied["trial_id"], head
            ):
                raise PermissionError(
                    "guard review differs from actual native evidence"
                )


def _completed_native_prefix(view, trial_id, expected_head):
    """A historical head must already contain this immutable six-branch result."""
    for head, progress in _native_progresses(view):
        if head != expected_head:
            continue
        trial = next(t for t in progress["trials"] if t["trial_id"] == trial_id)
        records = [r for r in progress["records"] if r["trial_id"] == trial_id]
        declared = next(
            t for t in view.registration["trials"] if t["trial_id"] == trial_id
        )
        expected_ids = {r["request_id"] for r in declared["branches"]}
        return (
            trial["status"] == "completed"
            and trial == view.trials[trial_id]
            and len(records) == len(expected_ids) == 6
            and {r["request_id"] for r in records} == expected_ids
            and all(
                r["status"] == "completed" and r == view.records[r["request_id"]]
                for r in records
            )
        )
    return False


def validate_first_dispatch_guard_evidence(
    context, request, view, source, settlement, prior_maximum
):
    from evals.timing_pool import _plain, _time
    from evals.timing_pool_controller import validate_first_dispatch_guard

    evidence = settlement["evidence"]
    pin = evidence["guard_receipt"]
    proof = _pin(pin)
    if (
        _plain(pin["path"])
        != context["reader"]._root
        / "artifacts"
        / "first-dispatch-guard"
        / pin["sha256"]
    ):
        raise PermissionError("first dispatch guard outside original host artifacts")
    validate_first_dispatch_guard(proof, source, prior_maximum)
    if (
        proof["trial_id"] != request.trial_id
        or proof["registration_sha256"] != canonical_hash(view.registration)
        or evidence["native"] != proof["native_snapshot"]
    ):
        raise PermissionError("first dispatch guard native identity differs")
    prefixes = dict(_native_progresses(view))
    start = prefixes.get(proof["native_start_head_sha256"])
    end = prefixes.get(proof["native_head_sha256"])
    if start is None or end != proof["native_snapshot"]:
        raise PermissionError("first dispatch guard is not an immutable native prefix")
    start_trial = next(t for t in start["trials"] if t["trial_id"] == request.trial_id)
    end_trial = next(t for t in end["trials"] if t["trial_id"] == request.trial_id)
    if (
        start_trial["status"] != "not_started"
        or start_trial.get("binding")
        or view.trials[request.trial_id] != end_trial
        or any(
            r["status"] != "not_started"
            for r in view.records.values()
            if r["trial_id"] == request.trial_id
        )
    ):
        raise PermissionError(
            "first dispatch guard reused or obscured native execution"
        )
    from hashlib import sha256

    workers = evidence["host_workers"]
    if [r["phase"] for r in workers["workers"]] != ["plan", "decision"] or not _time(
        proof["sampled_at"]
    ) <= _time(workers["inspected_at"]) <= _time(
        evidence["quiescence"]["inspected_at"]
    ):
        raise PermissionError(
            "guard resources lack fresh complete owned worker inspection"
        )
    for row in workers["workers"]:
        terminal = context["reader"]._terminal(request, row["phase"])
        if row["runtime_result"] != terminal["runtime_result"]:
            raise PermissionError("guard inspected different original worker")
        value = _pin(row["runtime_result"])
        container = value["isolation_evidence"]["container"]["container_id"]
        expected = {
            "argv": [
                "docker",
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                "id=" + container,
                "--format",
                "{{.ID}}",
            ],
            "returncode": 0,
            "stdout_sha256": sha256(b"").hexdigest(),
            "stderr_sha256": sha256(b"").hexdigest(),
        }
        if row["inspection"] != expected:
            raise PermissionError(
                "guard owned worker absence is not independently inspected"
            )
    decided = context["reader"]._terminal(request, "decision")
    actual = _pin(decided["runtime_result"])
    if proof["approval_receipt"] != actual["approval_receipt"] or not _time(
        source["state"]["approval"]["decided_at"]
    ) <= _time(proof["sampled_at"]) <= _time(evidence["quiescence"]["inspected_at"]):
        raise PermissionError(
            "first dispatch guard actual approval or sample time differs"
        )
