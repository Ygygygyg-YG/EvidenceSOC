"""Explicit native Task13 pool operations. Never creates consent or registrations.

Run phases individually: plan, read, decision (actual chat pin), trial. A pending
attempt blocks every other child. No operation synthesizes human approval.

Preload this object/serve with only the approved service DB/OpenSearch environment.
A reviewed outer operator may add only the selected provider credential for the
explicit plan phase after free admission, then remove it. Never pass credentials
through this JSON protocol, argv, stdout, or an unfiltered .env loader.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sqlite3
from datetime import UTC, datetime
from decimal import Decimal
from hashlib import sha256
from pathlib import Path

from evals.contracts import canonical_hash
from evals.timing_pool import (
    RECOVERY_REGISTRATION_SCHEMA,
    pool_policy,
    read_native_observation,
    validate_pool_receipt,
    validate_pool_registration,
    validate_pool_structure,
)
from evals.timing_pool_controller import PoolJournal, PoolStopped, _money
from evals.worker_lifecycle import _docker
from scripts.task13_e_trial import ETrialController, _decode, _read_pin


def derive_next_three_bound(host):
    """Execute only pinned native payload-building statements, never transport."""
    import ast
    from types import SimpleNamespace

    from evidencesoc.agents.models import ResponseOutput

    root = Path(__file__).resolve().parents[1]
    relatives = (
        "evals/adapters/model_client.py",
        "services/backend/src/evidencesoc/agents/models.py",
        "services/backend/src/evidencesoc/agents/diagnosis.py",
        "services/backend/src/evidencesoc/domain/models.py",
        "services/backend/src/evidencesoc/domain/response_action.py",
    )
    for relative in relatives:
        path = root / relative
        if (
            host._timing["source_files"].get(str(path))
            != sha256(path.read_bytes()).hexdigest()
        ):
            raise PoolStopped("capacity proof native source is not frozen")
    client = root / relatives[0]
    module = ast.parse(client.read_bytes())
    cls = next(
        n
        for n in module.body
        if isinstance(n, ast.ClassDef) and n.name == "TrackedModel"
    )
    fn = next(
        n
        for n in cls.body
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "structured"
    )

    def name(node):
        return (
            node.targets[0].id
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
            else None
        )

    first = next(i for i, n in enumerate(fn.body) if name(n) == "instruction")
    last = next(i for i, n in enumerate(fn.body) if name(n) == "encoded")
    nodes = fn.body[first : last + 1]
    expected = ast.parse(
        "((len(encoded) + 4096) * 2 + self.config.max_tokens * 8) / 1000000",
        mode="eval",
    ).body
    if len(nodes) != 5 or ast.dump(fn.body[last + 1].value) != ast.dump(expected):
        raise PoolStopped("native payload or peak reservation formula changed")
    request = host._requests[0].model_dump(mode="json")
    model = request["model"]
    if model["max_context_bytes"] != 65536 or model["max_tokens"] != 4096:
        raise PoolStopped("native capacity limits differ")
    context = next(n for n in fn.body if name(n) == "context_text")
    if (
        ast.unparse(context.value)
        != "json.dumps(context, ensure_ascii=False, default=str)"
        or "if len(context_text.encode()) > self.config.max_context_bytes:"
        not in ast.unparse(fn)
    ):
        raise PoolStopped("native encoded context bound differs")
    namespace = {
        "self": SimpleNamespace(
            config=SimpleNamespace(**model), entry_prompt=request["entry_prompt"]
        ),
        "role": "respond",
        "schema": ResponseOutput,
        "context_text": "",
        "json": json,
        "datetime": datetime,
        "UTC": UTC,
    }
    exec(  # noqa: S102 - only hash-pinned native payload construction; no dispatch statements.
        compile(ast.Module(body=nodes, type_ignores=[]), str(client), "exec"), namespace
    )
    skeleton = namespace["encoded"]
    if json.loads(skeleton)["messages"][-1] != {"role": "user", "content": ""}:
        raise PoolStopped("empty native payload differs")
    payload_upper = len(skeleton) + 32 + 2 * model["max_context_bytes"]
    return (
        (Decimal(payload_upper + 4096) * 2 + Decimal(4096) * 8) / Decimal(1000000) * 3
    )


def require_free_admission(
    pin, *, pool, host, request, now, spent, reserve, guard_review_sha256=None
):
    """Recheck raw per-attempt native-copy/service/reader proof before any claim.

    The separately frozen free helper produces this evidence without provider
    credentials or GO. This gate is never approval for the newly planned case.
    """
    from datetime import timedelta

    from evals.timing_pool_controller import DEADLINE, require_plain_path
    from scripts.task13_pool_admission import (
        validate_junit_check,
        validate_native_artifacts,
        validate_public_artifacts,
        validate_service_artifacts,
    )
    from scripts.task13_worker_runtime import validate_e_planning_probe

    try:
        if not pin:
            raise PoolStopped("fresh per-attempt free admission pin required")
        policy = pool["free_admission"]
        root = require_plain_path(policy["gate_root"])
        path = require_plain_path(pin["path"], file=True)
        if (
            path.parent != root / request.trial_id
            or re.fullmatch(r"[0-9a-f]{32}\.json", path.name) is None
        ):
            raise PoolStopped("free admission path differs from approved trial gate")
        gate = _decode(_read_pin(pin))
        expected = {
            "schema_version": "task13-host-readonly-paid-dispatch-gate-v1",
            "status": "passed",
            "phase": "pre_plan_no_new_case",
            "pool_registration_sha256": canonical_hash(pool),
            "trial_id": request.trial_id,
            "planning_request_sha256": canonical_hash(request),
            "source_commit": request.source_commit,
            "ordinal": request.ordinal,
            "host_manifest": host._manifest_pin,
            "guard_review_sha256": guard_review_sha256,
            "provider_requests": 0,
            "plan_approvals": 0,
            "timing_credit": 0,
            "plan_ttl_or_branch_budget_changes": False,
            "automatic_retry": False,
            "actual_new_case_reader_measured": False,
            "actual_six_branch_timing_measured": False,
        }
        if any(
            type(gate.get(k)) is not type(v) or gate.get(k) != v
            for k, v in expected.items()
        ):
            raise PoolStopped(
                "free admission trial/source/zero-provider binding differs"
            )
        checked = datetime.fromisoformat(gate["checked_at"])
        until = datetime.fromisoformat(gate["valid_until"])
        if (
            checked.tzinfo is None
            or until.tzinfo is None
            or not checked <= now < until
            or until > min(checked + timedelta(minutes=5), DEADLINE)
        ):
            raise PoolStopped("free admission expired or future-dated")
        refs = gate["evidence"]
        if (
            set(policy["helpers"]) != {"assembler", "native_probe", "services"}
            or refs["helpers"] != policy["helpers"]
        ):
            raise PoolStopped("free admission frozen helper set differs")
        for helper in policy["helpers"].values():
            _read_pin(helper)
            if host._timing["source_files"].get(helper["path"]) != helper["sha256"]:
                raise PoolStopped("free admission helper outside frozen native source")
        for name in ("reader-regression", "reader-lowlevel"):
            if refs[name] != policy[name.replace("-", "_")]:
                raise PoolStopped("free admission R1/R2 evidence pin differs")
        if not require_plain_path(
            refs["public-check"]["path"], file=True
        ).is_relative_to(root):
            raise PoolStopped("free admission price guard outside approved gate root")
        native, services, public, regression, lowlevel = [
            _decode(_read_pin(refs[name]))
            for name in (
                "native",
                "services",
                "public-check",
                "reader-regression",
                "reader-lowlevel",
            )
        ]
        validate_native_artifacts(native, host, request, root=root)
        validate_service_artifacts(services, host, request, root=root)
        native_expected = {
            "schema_version": "task13-startup-native-verification-v1",
            "status": "passed",
            "source_commit": request.source_commit,
            "network": "none",
            "original_account_writes": False,
            "copied_budget_and_journal": True,
            "provider_key_read": False,
            "provider_calls": 0,
            "GO_sent": False,
            "actual_timing_credit": 0,
            "container_absent": True,
        }
        if any(
            type(native.get(k)) is not type(v) or native.get(k) != v
            for k, v in native_expected.items()
        ):
            raise PoolStopped("free admission native copy/cleanup proof differs")
        duration = native["probe_elapsed_seconds"]
        if type(duration) not in (int, float) or not 0 < duration < 120:
            raise PoolStopped(
                "free admission native startup exceeds original 120 seconds"
            )
        validate_e_planning_probe(
            native["probe"]["planning"],
            request,
            authority_sha256=host._inputs["runtime_options"][
                "planning_authority_sha256"
            ],
        )
        service_expected = {
            "schema_version": "task13-e-service-environment-preflight-v1",
            "status": "verified",
            "source_commit": request.source_commit,
            "service_checks_passed": True,
            "container_absent": True,
            "errors": [],
            "provider_credentials_parsed_or_injected": False,
            "paid_calls": 0,
            "real_plan_approvals": 0,
            "real_timing_credit": 0,
        }
        if any(
            type(services.get(k)) is not type(v) or services.get(k) != v
            for k, v in service_expected.items()
        ):
            raise PoolStopped("free admission service/cleanup proof differs")
        sr = services["result"]
        if (
            sr.get("postgres_select1") is not True
            or sr.get("opensearch_http_status") != 200
            or sr.get("queries_read_only") is not True
            or sr.get("model_calls") != 0
            or sr.get("provider_keys_present") is not False
        ):
            raise PoolStopped(
                "free admission original read-only services not established"
            )
        if (
            public.get("status") != "public_spec_matches_pending_runtime_check"
            or public.get("blockers") != []
        ):
            raise PoolStopped("free admission public model/price check failed")
        reference = _decode(_read_pin(policy["public_reference"]))
        validate_public_artifacts(public, reference, request, root=root)
        if (
            public.get("expected_frozen_model") != request.model.model_dump(mode="json")
            or public.get("observed_flash_rates_cny_per_million")
            != reference["expected_flash_rates_cny_per_million"]
            or public.get("official_document_get_requests") != 2
            or any(
                public.get(k) != 0
                for k in (
                    "new_paid_calls",
                    "provider_chat_completions_requests",
                    "model_list_requests",
                    "search_or_fetch_api_requests",
                    "registrations_by_this_check",
                )
            )
            or public.get("credential_or_env_file_reads") is not False
            or public.get("database_access") is not False
        ):
            raise PoolStopped(
                "free admission actual public model/price/zero-provider proof differs"
            )
        expected_urls = {
            "official-pricing": "https://api-docs.deepseek.com/zh-cn/quick_start/pricing/",
            "official-thinking-mode": "https://api-docs.deepseek.com/zh-cn/guides/thinking_mode/",
        }
        if set(public["public_fetches"]) != set(expected_urls):
            raise PoolStopped("free admission official-document sources differ")
        for name, url in expected_urls.items():
            fetch = public["public_fetches"][name]
            if (
                fetch["official_url"] != url
                or fetch["response_url"] != url
                or fetch["http_status"] != 200
            ):
                raise PoolStopped("free admission official-document response differs")
            _read_pin(fetch["html"])
            _read_pin(fetch["text"])
        public_time = datetime.fromisoformat(
            public.get("checked_at", public.get("created_at_utc"))
        )
        if (
            public_time.tzinfo is None
            or not 0 <= (now - public_time).total_seconds() <= 300
        ):
            raise PoolStopped("free admission public price evidence stale")
        for stamp in (
            native["finished_at"],
            services["finished_at"],
            public.get("checked_at", public.get("created_at_utc")),
        ):
            when = datetime.fromisoformat(stamp)
            if when.tzinfo is None or not 0 <= (now - when).total_seconds() <= 1800:
                raise PoolStopped("free admission live prerequisites stale")
        for name in ("regression", "final-neighbor"):
            check = regression["tests"][name]
            validate_junit_check(check)
            if (
                check["tests"] <= 0
                or any(check[k] != 0 for k in ("failures", "errors", "skipped"))
                or not _read_pin(check["junit"])
            ):
                raise PoolStopped("free admission frozen R1/R2 regression failed")
        if (
            lowlevel.get("status") != "passed"
            or lowlevel.get("diagnostic_only") is not True
            or lowlevel.get("live_state_equals_retained") is not True
            or any(
                lowlevel.get(k) != 0
                for k in (
                    "new_provider_calls",
                    "new_plan_approvals",
                    "new_timing_credit",
                )
            )
            or any(
                lowlevel["host_read_receipt"].get(k) != "on"
                for k in (
                    "checkpoint_transaction_read_only",
                    "business_transaction_read_only",
                )
            )
        ):
            raise PoolStopped("free admission low-level R1/R2 read evidence differs")
        budget = gate["read_only_budget"]
        if (
            budget.get("read_only") is not True
            or budget["original_budget_identity"] != request.budget_identity
            or _money(budget["development_spent_yuan"]) != spent
            or _money(gate["next_three_upper_cny"]) != reserve
        ):
            raise PoolStopped("free admission fresh budget/capacity snapshot differs")
        return {
            "path": str(path),
            "sha256": pin["sha256"],
            "checked_at": checked.isoformat(),
        }
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise PoolStopped(
            "invalid free admission evidence: " + type(error).__name__
        ) from error


def recheck_free_admission_claim(pin, pool_digest, request, guard_review_sha256=None):
    """Under the parent writer lock, recheck the explicit immutable gate pin."""
    from evals.timing_pool_controller import DEADLINE

    gate = _decode(_read_pin(pin))
    now = datetime.now(UTC)
    checked = datetime.fromisoformat(gate["checked_at"])
    until = datetime.fromisoformat(gate["valid_until"])
    if (
        gate["pool_registration_sha256"] != pool_digest
        or gate.get("guard_review_sha256") != guard_review_sha256
        or gate["trial_id"] != request.trial_id
        or gate["planning_request_sha256"] != canonical_hash(request)
        or checked.tzinfo is None
        or until.tzinfo is None
        or not checked <= now < until
        or now >= DEADLINE
    ):
        raise PoolStopped("free admission changed or expired before locked BEGIN")


class NativePoolController:
    """Pinned actual native hosts only; no injectable production executor."""

    def __init__(self, manifest_path, manifest_sha256):
        self.pin = {"path": str(manifest_path), "sha256": manifest_sha256}
        self.raw = _read_pin(self.pin)
        self.manifest = _decode(self.raw)
        if self.manifest["schema_version"] not in {
            "task13-e-timing-pool-host-v1",
            "task13-e-timing-pool-host-v2",
        }:
            raise PoolStopped("pool host manifest schema differs")
        self.pool = validate_pool_registration(
            _decode(_read_pin(self.manifest["pool_registration"]))
        )
        expected_host = (
            "task13-e-timing-pool-host-v2"
            if pool_policy(self.pool).future_logical_limit == 5
            else "task13-e-timing-pool-host-v1"
        )
        if self.manifest["schema_version"] != expected_host:
            raise PoolStopped("pool host and registration version differ")
        if (
            self.pool["schema_version"] == RECOVERY_REGISTRATION_SCHEMA
            and self.manifest["migration_marker"] != self.pool["quarantine_record"]
        ):
            raise PoolStopped("pool host quarantine raw reference differs")
        if (
            self.manifest["original_account_baseline"]
            != self.pool["original_account_baseline"]
        ):
            raise PoolStopped("original account baseline is not bound to parent scope")
        self.digest = canonical_hash(self.pool)
        if (
            self.manifest["journal_path"] != self.pool["execution_journal_path"]
            or Path(self.manifest["journal_path"]).name != "pool-journal.jsonl"
        ):
            raise PoolStopped("pool journal path differs from approved parent proposal")
        self.journal = PoolJournal(
            self.manifest["journal_path"],
            pool_sha256=self.digest,
            policy=pool_policy(self.pool),
        )
        self.hosts = {}
        for child in self.pool["children"]:
            pin = self.manifest["hosts"][child["child_id"]]
            host = ETrialController(pin["path"], pin["sha256"])
            if (
                host._manifest["synthetic"]
                or host._inputs.get("pool_authority") != self.pool
                or host._timing != child["registration"]
                or str(host._root / "timing") != child["evidence_root"]
            ):
                raise PoolStopped("actual child host and pool membership differ")
            self.hosts[child["child_id"]] = host
        for key in ("scope_packet", "scope_decision"):
            if (
                len({h._manifest["inputs"][key]["sha256"] for h in self.hosts.values()})
                != 1
            ):
                raise PoolStopped(
                    "both native children require the same actual parent scope and decision"
                )
        accounts = {
            str(h._inputs["runtime_options"]["budget_dir"]) for h in self.hosts.values()
        }
        if len(accounts) != 1:
            raise PoolStopped("pool must retain one original shared budget account")
        self.budget_path = Path(next(iter(accounts))) / "campaign.sqlite"

    def guard(self):
        if _read_pin(self.pin) != self.raw:
            raise PoolStopped("frozen pool host changed")
        validate_pool_structure(self.pool)
        from evals.timing_pool import validate_migration_marker

        if (
            self.pool["schema_version"] == RECOVERY_REGISTRATION_SCHEMA
            and self.manifest["migration_marker"] != self.pool["quarantine_record"]
        ):
            raise PoolStopped("pool host quarantine raw reference differs")

        first_host = next(iter(self.hosts.values()))
        validate_migration_marker(
            _decode(_read_pin(self.manifest["migration_marker"])),
            self.pool,
            first_host._manifest["inputs"]["scope_packet"],
            first_host._manifest["inputs"]["scope_decision"],
        )
        for host in self.hosts.values():
            host._preflight(host._requests[0])
        if self.pool["schema_version"] == RECOVERY_REGISTRATION_SCHEMA:
            from types import SimpleNamespace

            from evals.timing_pool import _view, validate_denied_native_slot

            for denied in self.pool["denied_attempts"]:
                host = self.hosts[denied["child_id"]]
                host._journal()  # Original native metadata validates every SQL claim.
                request = next(
                    r for r in host._requests if r.trial_id == denied["trial_id"]
                )
                root = host._root / "timing"
                if (root / "registration.json").exists():
                    view = _view(root)
                else:
                    if root.exists() and any(root.rglob("*")):
                        raise PoolStopped(
                            "denied slot has unregistered timing evidence"
                        )
                    view = SimpleNamespace(
                        trials={
                            request.trial_id: {"status": "not_started", "binding": None}
                        },
                        records={},
                    )
                context = {
                    "reader": host,
                    "claims": {request.trial_id: {"status": "unclaimed"}},
                    "planning_journal_path": host._inputs["planning_authority"][
                        "journal_path"
                    ],
                }
                validate_denied_native_slot(context, request, view)

    def budget(self):
        # Read only. Native BudgetAccount still enforces original and supplement caps.
        from evals.adapters.remediation_worker import _budget_snapshot

        values, original_rows = _budget_snapshot(self.budget_path)
        baseline = _decode(_read_pin(self.manifest["original_account_baseline"]))
        if values != baseline["config"]:
            raise PoolStopped("original account config or halt changed")
        with sqlite3.connect(
            self.budget_path.resolve().as_uri() + "?mode=ro", uri=True
        ) as db:
            rows = db.execute(
                "SELECT r.id,r.actual,r.settled,s.purpose,s.request_id,s.role FROM reservations r JOIN supplement_requests s ON s.reservation_id=r.id"
            ).fetchall()
        supplement_ids = {r[0] for r in rows}
        unknown = [
            list(r)
            for r in original_rows
            if r[0] is not None
            and r[1] not in supplement_ids
            and (r[6] != 1 or r[5] is None)
        ]
        if unknown != baseline["legacy_unknown_rows"]:
            raise PoolStopped(
                "historical held reservations changed or new unknown cost"
            )
        if any(r[2] != 1 or r[1] is None for r in rows):
            raise PoolStopped("unknown supplement cost or inflight reservation")
        if len({r[0] for r in rows}) != len(rows) or len({r[4] for r in rows}) != len(
            rows
        ):
            raise PoolStopped("duplicate supplement ledger attribution")
        return sum((_money(r[1]) for r in rows if r[3] == "development"), Decimal(0))

    async def quiescence(self):
        """Fresh daemon check of owned workers from content-bound native host receipts."""
        proofs = []
        environment = {
            key: os.environ[key]
            for key in (
                "PATH",
                "SYSTEMROOT",
                "WINDIR",
                "TEMP",
                "TMP",
                "USERPROFILE",
                "DOCKER_HOST",
                "DOCKER_CONTEXT",
            )
            if key in os.environ
        }
        from evals.timing_pool_controller import require_plain_path

        for host in self.hosts.values():
            require_plain_path(host._termination)
            if host._termination.exists() and not host._termination.is_dir():
                raise PoolStopped("owned termination root is not a directory")
            for entry in host._termination.rglob("*"):
                require_plain_path(entry, file=entry.is_file())
            for path in host._termination.glob("*/*.json"):
                require_plain_path(path, file=True)
                if not path.is_relative_to(host._termination):
                    raise PoolStopped("termination proof outside owned root")
                raw = path.read_bytes()
                value = _decode(raw)
                digest = sha256(raw).hexdigest()
                nonce = value.get("worker_nonce", "")
                container_id = value.get("container_id", "")
                if (
                    re.fullmatch("[0-9a-f]{32}", nonce) is None
                    or re.fullmatch("[0-9a-f]{64}", container_id) is None
                    or path.name != nonce + "-" + digest + ".json"
                    or value.get("status") != "verified"
                    or value.get("host_process_exited") is not True
                    or value.get("container_name") != "task13-worker-" + nonce
                ):
                    raise PoolStopped("unknown native worker termination")
                record, stdout = await _docker(
                    [
                        "container",
                        "ls",
                        "--all",
                        "--no-trunc",
                        "--filter",
                        "id=" + container_id,
                        "--format",
                        "{{.ID}}",
                    ],
                    environment,
                )
                if record.get("returncode") != 0 or stdout is None or stdout.strip():
                    raise PoolStopped("owned native worker is not freshly absent")
                proofs.append({"receipt_sha256": digest, "inspection": record})
        proof = {"inspected_at": datetime.now(UTC).isoformat(), "proofs": proofs}
        if self.pool["schema_version"] == RECOVERY_REGISTRATION_SCHEMA:
            from evals.timing_pool import validate_recovery_quarantine
            from evals.timing_pool_recovery import fresh_quarantine_workers_absent

            quarantine = validate_recovery_quarantine(self.pool)
            proof["quarantined_predecessor_workers"] = await asyncio.to_thread(
                fresh_quarantine_workers_absent, quarantine
            )
            proof["inspected_at"] = datetime.now(UTC).isoformat()
        return proof

    def reserve_bound(self):
        proof = _decode(_read_pin(self.manifest["capacity_proof"]))
        if (
            proof["schema_version"] != "task13-pool-next-three-capacity-v1"
            or proof["pool_registration_sha256"] != self.digest
            or proof["physical_requests"] != 3
            or proof["max_tokens"] != 4096
            or proof["peak_input_cny_per_million"] != 2
            or proof["peak_output_cny_per_million"] != 8
            or not proof["supporting_refs"]
            or not proof["bound_basis"].strip()
        ):
            raise PoolStopped("pinned next-three capacity proof differs")
        for pin in proof["supporting_refs"]:
            _read_pin(pin)
        upper = (
            Decimal(proof["payload_bytes_upper_bound"] + 4096) * 2 + Decimal(4096) * 8
        ) / Decimal(1000000)
        if _money(proof["next_three_upper_cny"]) != upper * 3:
            raise PoolStopped("next-three capacity arithmetic differs")
        derived = max(derive_next_three_bound(host) for host in self.hosts.values())
        if upper * 3 != derived:
            raise PoolStopped(
                "capacity proof differs from freshly derived native payload"
            )
        return derived

    async def prepare(self):
        self.guard()
        spent = self.budget()
        await self.quiescence()
        original = read_native_observation(
            self.pool["imported_observations"][0]["evidence_root"],
            self.pool["imported_observations"][0]["trial_id"],
            evidence_archives=self.pool.get("evidence_archives"),
        )
        self.journal = PoolJournal.prepare(
            self.journal.path,
            pool_sha256=self.digest,
            attempts=[a["trial_id"] for a in self.pool["attempt_order"]],
            imported_trial_id=original["trial_id"],
            now=datetime.now(UTC),
            initial_spent_yuan=str(spent),
            policy=pool_policy(self.pool),
            migration_grant=self.pool.get("migration_grant"),
            quarantined_predecessor=self.pool.get("quarantined_predecessor"),
            imported_max_seconds=max(
                original["duration_wall_seconds"],
                original["duration_monotonic_seconds"],
            ),
        )
        return self.journal.status()

    async def _first_guard_workers_absent(self, host, request):
        environment = {
            k: os.environ[k]
            for k in (
                "PATH",
                "SYSTEMROOT",
                "WINDIR",
                "TEMP",
                "TMP",
                "USERPROFILE",
                "DOCKER_HOST",
                "DOCKER_CONTEXT",
            )
            if k in os.environ
        }
        workers = []
        for phase in ("plan", "decision"):
            terminal = host._terminal(request, phase)
            if not terminal or terminal["status"] not in {
                "awaiting_approval",
                "approved",
            }:
                raise PoolStopped("guard worker terminal is unknown")
            pin = terminal["runtime_result"]
            value = _decode(_read_pin(pin))
            container = value["isolation_evidence"]["container"]["container_id"]
            if re.fullmatch("[0-9a-f]{64}", container) is None:
                raise PoolStopped("guard owned container identity invalid")
            record, stdout = await _docker(
                [
                    "container",
                    "ls",
                    "--all",
                    "--no-trunc",
                    "--filter",
                    "id=" + container,
                    "--format",
                    "{{.ID}}",
                ],
                environment,
            )
            if record.get("returncode") != 0 or stdout is None or stdout.strip():
                raise PoolStopped("guard owned container absence is unknown")
            workers.append(
                {"phase": phase, "runtime_result": pin, "inspection": record}
            )
        return {"inspected_at": host._now().isoformat(), "workers": workers}

    async def run(
        self, phase, *, packet_sha256=None, chat_record=None, free_admission_pin=None
    ):
        self.guard()
        spent = self.budget()
        proof = await self.quiescence()
        state = self.journal.status()
        if state["stopped"]:
            raise PoolStopped("STOP: " + state["stopped"])
        if phase == "plan":
            if state["observed_max_seconds"] > 800:
                from evals.timing_pool_controller import require_current_guard_review
                from evals.timing_pool_evidence import validate_controller_evidence

                require_current_guard_review(
                    self.journal._events(),
                    self.digest,
                    datetime.now(UTC),
                    state["observed_max_seconds"],
                )
                original_ref = self.pool["imported_observations"][0]
                original = read_native_observation(
                    original_ref["evidence_root"],
                    original_ref["trial_id"],
                    evidence_archives=self.pool.get("evidence_archives"),
                )
                validate_controller_evidence(
                    self.controller_evidence(),
                    self.pool,
                    original,
                    require_complete=False,
                )
            if state["attempted"] >= pool_policy(self.pool).future_logical_limit:
                raise PoolStopped("pool exhausted")
            attempt = self.pool["attempt_order"][state["attempted"]]
            reserve = self.reserve_bound()
            target_host = self.hosts[attempt["child_id"]]
            target_request = next(
                r for r in target_host._requests if r.trial_id == attempt["trial_id"]
            )
            admission = require_free_admission(
                free_admission_pin,
                pool=self.pool,
                host=target_host,
                request=target_request,
                now=datetime.now(UTC),
                spent=spent,
                reserve=reserve,
                guard_review_sha256=state["journal_head"]
                if state["observed_max_seconds"] > 800
                else None,
            )
            if spent + reserve > 6:
                raise PoolStopped("actual development budget cap")
            self.journal.begin(
                attempt["trial_id"],
                now=datetime.now(UTC),
                quiescent=True,
                reserved_yuan=reserve,
                before_claim=lambda: recheck_free_admission_claim(
                    free_admission_pin,
                    self.digest,
                    target_request,
                    self.journal.status()["journal_head"]
                    if self.journal.status()["observed_max_seconds"] > 800
                    else None,
                ),
            )
        else:
            if not state["pending"]:
                raise PoolStopped("no pending native attempt")
            attempt = next(
                a
                for a in self.pool["attempt_order"]
                if a["trial_id"] == state["pending"]
            )
        host = self.hosts[attempt["child_id"]]
        ordinal = next(
            r.ordinal for r in host._requests if r.trial_id == attempt["trial_id"]
        )
        # Hold pool lock throughout native operation; child locks and every native
        # request/TTL/approval/source/lifecycle guard still execute normally.
        with self.journal.lock() as owner:
            events = self.journal._events()
            claims = [
                e
                for e in events
                if e["kind"] == "phase_claim"
                and e["payload"]["trial_id"] == attempt["trial_id"]
                and e["payload"]["phase"] == phase
            ]
            finishes = [
                e
                for e in events
                if e["kind"] == "phase_finish"
                and e["payload"]["trial_id"] == attempt["trial_id"]
                and e["payload"]["phase"] == phase
            ]
            if claims and (phase != "read" or len(claims) != len(finishes)):
                raise PoolStopped(
                    "native phase already claimed; audit unknown execution"
                )
            self.journal._append(
                "phase_claim",
                {
                    "trial_id": attempt["trial_id"],
                    "phase": phase,
                    "quiescence": proof,
                    "child_id": attempt["child_id"],
                    **({"free_admission": admission} if phase == "plan" else {}),
                    **(
                        {"chat_record": chat_record, "packet_sha256": packet_sha256}
                        if phase == "decision"
                        else {}
                    ),
                },
                events,
            )
            from evals.timing_pool_controller import PoolPhaseLease

            host._pool_lease = PoolPhaseLease(
                self.journal.path,
                owner["nonce"],
                self.journal._events()[-1]["sha256"],
                attempt["child_id"],
                attempt["trial_id"],
                phase,
            )
            try:
                if phase == "decision":
                    result = await host.decision(
                        ordinal, packet_sha256=packet_sha256, chat_record=chat_record
                    )
                else:
                    result = await getattr(host, phase)(ordinal)
                self.journal._append(
                    "phase_finish",
                    {
                        "trial_id": attempt["trial_id"],
                        "phase": phase,
                        "result_sha256": canonical_hash(result),
                    },
                    self.journal._events(),
                )
            except BaseException:
                self.journal._append(
                    "stop",
                    {"reason": "unknown_native_execution"},
                    self.journal._events(),
                )
                raise
            finally:
                host._pool_lease = None
        if phase == "trial":
            native = host._campaign().snapshot()
            terminal = next(
                t for t in native["trials"] if t["trial_id"] == attempt["trial_id"]
            )
            after = self.budget()
            fresh = await self.quiescence()
            guard_evidence = None
            if result.get("status") == "ttl_guard_rejected":
                try:
                    from evals.timing_pool_controller import (
                        validate_first_dispatch_guard,
                    )

                    request = host._requests[ordinal - 1]
                    decided = host._terminal(request, "decision")
                    actual = _decode(_read_pin(decided["runtime_result"]))
                    retained, resources = host._retained(request)
                    source = host._source(
                        request, actual["source"]["state"], retained, resources
                    )
                    guard_proof = _decode(_read_pin(result["guard_receipt"]))
                    validate_first_dispatch_guard(
                        guard_proof, source, state["observed_max_seconds"]
                    )
                    if (
                        guard_proof["native_snapshot"] != native
                        or guard_proof["approval_receipt"] != actual["approval_receipt"]
                    ):
                        raise PoolStopped(
                            "first dispatch guard original evidence differs"
                        )
                    host_workers = await self._first_guard_workers_absent(host, request)
                    fresh = await self.quiescence()
                    if self.budget() != after:
                        raise PoolStopped("guard cost changed during settlement")
                    guard_evidence = {
                        "host_workers": host_workers,
                        "subtype": "first_dispatch_ttl_guard",
                        "guard_receipt": result["guard_receipt"],
                        "native": native,
                        "quiescence": fresh,
                    }
                    observation = native
                    outcome = "ttl_infrastructure_failure"
                    maximum = 0
                except BaseException:
                    self.journal.stop("unknown_native_execution")
                    raise
            elif terminal["status"] == "completed":
                observation = read_native_observation(
                    str(host._root / "timing"), attempt["trial_id"]
                )
                outcome = "qualified"
                maximum = max(
                    observation["duration_wall_seconds"],
                    observation["duration_monotonic_seconds"],
                )
            elif terminal["status"] in {"expired", "failed", "rejected"} and terminal[
                "reason"
            ] in {
                "plan_expired",
                "trial_hard_deadline",
                "receipt_after_plan_expiry",
                "bootstrap_remaining_must_exceed_1500",
                "provisional_remaining",
                "remaining_changed_before_dispatch",
            }:
                # Native journal is terminal, all charged calls settled, and every
                # owned worker freshly absent. No previously claimed phase replays.
                observation = terminal
                outcome = "ttl_infrastructure_failure"
                maximum = 0
            else:
                self.journal.stop("unqualified_native_terminal")
                raise PoolStopped(
                    "native terminal is not a settled recognized TTL failure"
                )
            self.journal.settle(
                attempt["trial_id"],
                outcome=outcome,
                actual_yuan=str(after - _money(state["spent_yuan"])),
                quiescent=True,
                observed_max_seconds=maximum,
                evidence_sha256=canonical_hash(
                    guard_evidence or {"native": observation, "quiescence": fresh}
                ),
                evidence=guard_evidence or {"native": observation, "quiescence": fresh},
            )
        elif result.get("status") in {"blocked", "rejected", "unknown"}:
            self.journal.stop("native_" + result["status"])
        return result

    def _expiry_planning_ledger(self, host, request):
        plan = host._terminal(request, "plan")
        runtime = _decode(_read_pin(plan["runtime_result"]))
        ledger = runtime["model_ledger"]
        if not 1 <= len(ledger) <= 3 or len(
            {r["reservation_id"] for r in ledger}
        ) != len(ledger):
            raise PoolStopped("expiry requires every unique planning physical row")
        if len({r["logical_call_id"] for r in ledger}) != 1 or sorted(
            r["physical_attempt"] for r in ledger
        ) != list(range(1, len(ledger) + 1)):
            raise PoolStopped(
                "expiry complete single-logical physical sequence differs"
            )
        rows = []
        with sqlite3.connect(
            self.budget_path.resolve().as_uri() + "?mode=ro", uri=True
        ) as db:
            db.execute("PRAGMA query_only=ON")
            db.execute("BEGIN")
            all_ids = {
                r[0]
                for r in db.execute(
                    "SELECT reservation_id FROM supplement_requests WHERE logical_call_id=?",
                    (ledger[0]["logical_call_id"],),
                )
            }
            if all_ids != {r["reservation_id"] for r in ledger}:
                raise PoolStopped("expiry native physical ledger is incomplete")
            for record in ledger:
                matches = db.execute(
                    "SELECT r.actual,r.settled,r.request_key,s.request_id,s.case_id,s.role,s.purpose,s.source_sha256,s.config_sha256,s.request_sha256,s.physical_attempt,e.epoch_id,m.model_epoch_id,m.identity_manifest_sha256 FROM reservations r JOIN supplement_requests s ON s.reservation_id=r.id JOIN supplement_request_epochs e ON e.reservation_id=r.id JOIN supplement_request_models m ON m.reservation_id=r.id WHERE r.id=?",
                    (record["reservation_id"],),
                ).fetchall()
                if len(matches) != 1:
                    raise PoolStopped("expiry planning ledger missing or duplicated")
                row = matches[0]
                binding = request.model_identity_binding
                if (
                    row[1] != 1
                    or row[0] is None
                    or record.get("cost_cny") is None
                    or _money(row[0]) != _money(record["cost_cny"])
                    or row[2] != record["physical_request_id"]
                    or row[3] != record["physical_request_id"]
                    or row[4] != request.case_id
                    or row[5:7] != ("respond", "development")
                    or row[7] != request.source_sha256
                    or row[8] != request.config_sha256
                    or row[9] != record["request_sha256"]
                    or row[10] != record["physical_attempt"]
                    or row[11] != request.epoch_id
                    or binding is None
                    or row[12] != binding.model_epoch_id
                    or row[13] != binding.model_identity_sha256
                ):
                    raise PoolStopped(
                        "expiry physical ledger source/model/fee attribution differs"
                    )
                rows.append(
                    {
                        "reservation_id": record["reservation_id"],
                        "physical_request_id": record["physical_request_id"],
                        "settled": row[1],
                        "actual": row[0],
                        "expected_cost": record["cost_cny"],
                        "native_ledger_record": record,
                        "joined_row": list(row),
                    }
                )
        return rows

    async def audit_expiry(self, *, chat_records=()):
        """Inspect an expired, never-executed pending plan without any phase replay."""
        from contextlib import ExitStack

        from evals.adapters.e_planning_review import build_review_request
        from evals.e_timing import _validate_replicate_source
        from evals.host_review import read_e_planning_host_review
        from evals.timing_pool import _view
        from evals.timing_pool_controller import (
            close_pre_timing_expiry,
            require_plain_path,
        )
        from scripts.task13_e_trial import _bytes

        self.guard()
        with self.journal.lock() as owner, ExitStack() as native_stack:
            state = self.journal.status()
            if not state["pending"] or state["stopped"] not in (
                None,
                "unknown_native_execution",
                "native_unknown",
            ):
                raise PoolStopped("expiry audit cannot clear a hard STOP or empty pool")
            attempt = next(
                a
                for a in self.pool["attempt_order"]
                if a["trial_id"] == state["pending"]
            )
            host = self.hosts[attempt["child_id"]]
            request = next(r for r in host._requests if r.trial_id == state["pending"])
            try:
                native_stack.enter_context(host._lock())
                host._preflight(request, review=True)
                retained, resources = host._retained(request)
                decision_terminal = host._terminal(request, "decision")
                if decision_terminal is not None:
                    raise PoolStopped(
                        "attempted or unknown native decision cannot become pre-timing expiry"
                    )
                pins = list(chat_records)
                for event in self.journal._events():
                    payload = event["payload"]
                    if payload.get("trial_id") == request.trial_id and payload.get(
                        "chat_record"
                    ):
                        pins.append(payload["chat_record"])
                started = host._slot(request) / "decision-started.json"
                if started.exists():
                    raise PoolStopped(
                        "started native decision remains outside never-started expiry recovery"
                    )
                decisions = []
                seen = set()
                for pin in pins:
                    raw = _read_pin(pin)
                    if pin["sha256"] in seen:
                        continue
                    seen.add(pin["sha256"])
                    record = _decode(raw)
                    host._chat(
                        record,
                        kind="plan",
                        participation_policy=request.participation_policy,
                    )
                    if (
                        record.get("case_id") != request.case_id
                        or record.get("incident_id") != request.incident_id
                        or record.get("decision") != "approved"
                    ):
                        raise PoolStopped(
                            "actual rejection or different-case chat prevents expiry recovery"
                        )
                    decisions.append({"pin": pin, "record": record})
                before = self.budget()
                rows = self._expiry_planning_ledger(host, request)
                review = build_review_request(
                    request, resources, operation="read_packet"
                )
                live = await read_e_planning_host_review(
                    review, host._agent, host._options("verification")
                )
                expected_resources = {
                    key: resources[key]
                    for key in (
                        "database_name",
                        "index_name",
                        "incident_id",
                        "source_commit",
                    )
                }
                if live["source"]["resources"] != expected_resources or live[
                    "host_read_receipt"
                ]["resources_sha256"] != canonical_hash(review.case_resource):
                    raise PoolStopped("expiry actual original resources unknown")
                _validate_replicate_source(
                    host._timing,
                    host._timing["trials"][request.ordinal - 1],
                    host._source(request, live["source"]["state"], retained, resources),
                )
                read_pin = host._save("host-review-result", _bytes(live))
                receipt_pin = host._save(
                    "host-review-read", _bytes(live["host_read_receipt"])
                )
                timing_root = require_plain_path(host._root / "timing")
                if (timing_root / ".writer-lock").exists():
                    raise PoolStopped("native timing writer active or unknown")
                if (timing_root / "registration.json").exists():
                    native = _view(timing_root)._progress()
                else:
                    if timing_root.exists() and any(timing_root.iterdir()):
                        raise PoolStopped(
                            "unregistered native timing artifacts are unknown"
                        )
                    native = {
                        "journal_exists": False,
                        "registration_sha256": canonical_hash(host._timing),
                        "trials": [
                            {
                                "trial_id": t["trial_id"],
                                "status": "not_started",
                                "binding": None,
                            }
                            for t in host._timing["trials"]
                        ],
                        "records": [],
                    }
                quiet = await self.quiescence()
                after = self.budget()
                audit = {
                    "schema_version": "task13-pool-pre-timing-expiry-v1",
                    "trial_id": request.trial_id,
                    "request_sha256": canonical_hash(request),
                    "checked_at": datetime.now(UTC).isoformat(),
                    "review_request": review.model_dump(mode="json"),
                    "host_review_result": live,
                    "host_review_result_pin": read_pin,
                    "host_read_receipt_pin": receipt_pin,
                    "retained_state": retained,
                    "resources": resources,
                    "native_snapshot": native,
                    "decision_records": decisions,
                    "planning_ledger_rows": rows,
                    "budget_before_yuan": str(before),
                    "budget_after_yuan": str(after),
                }
                evidence = {
                    "subtype": "pre_timing_expired",
                    "audit": audit,
                    "quiescence": quiet,
                }
                return close_pre_timing_expiry(
                    self.journal, request.trial_id, evidence, _owner=owner
                )
            except BaseException:
                self.journal._append(
                    "stop", {"reason": "expiry_audit_unproven"}, self.journal._events()
                )
                raise

    def review_guard(self):
        """Free full evidence review; conveys no approval or permission to execute."""
        from evals.timing_pool_controller import (
            GUARD_FORMULA,
            shared_remaining_threshold,
            validate_guard_review,
        )
        from evals.timing_pool_evidence import (
            guard_observations,
            validate_controller_evidence,
        )

        self.guard()
        with self.journal.lock():
            state = self.journal.status()
            if state["pending"] or state["stopped"] or state["qualified"] >= 3:
                raise PoolStopped("guard review requires a closed unfinished pool")
            shared_remaining_threshold(state["observed_max_seconds"])
            original_ref = self.pool["imported_observations"][0]
            original = read_native_observation(
                original_ref["evidence_root"],
                original_ref["trial_id"],
                evidence_archives=self.pool.get("evidence_archives"),
            )
            verified = validate_controller_evidence(
                self.controller_evidence(), self.pool, original, require_complete=False
            )
            observations = guard_observations(
                self.pool, verified["qualified_trial_ids"]
            )
            events = self.journal._events()
            proof = {
                "schema_version": "task13-pool-guard-review-v1",
                "pool_registration_sha256": self.digest,
                "journal_head_sha256": events[-1]["sha256"],
                "checked_at": datetime.now(UTC).isoformat(),
                "formula_version": GUARD_FORMULA,
                "observations": observations,
                "settlement_evidence_sha256": [
                    p["evidence_sha256"] for p in verified["transcript"]["settlements"]
                ],
                "observed_max_seconds": state["observed_max_seconds"],
            }
            validate_guard_review(
                proof,
                self.digest,
                events,
                datetime.now(UTC),
                state["observed_max_seconds"],
            )
            self.journal._append("guard_review", proof, events)
            return self.journal.status()

    async def resume(self):
        self.guard()
        before = self.budget()
        fresh = await self.quiescence()
        if self.budget() != before:
            raise PoolStopped("fresh guard changed cost account")
        self.journal.resume(
            quiescent=True,
            fresh_guard_sha256=canonical_hash(fresh),
            guard_cost_yuan="0",
            guard_evidence=fresh,
        )
        return self.journal.status()

    def controller_evidence(self):
        raw = self.journal.path.read_bytes()
        return {
            "pool_journal": {
                "path": str(self.journal.path),
                "sha256": sha256(raw).hexdigest(),
                "head_sha256": self.journal._events()[-1]["sha256"],
            },
            "pool_host_manifest": self.pin,
            "parent_scope_packets": [
                h._manifest["inputs"]["scope_packet"] for h in self.hosts.values()
            ],
            "parent_scope_decisions": [
                h._manifest["inputs"]["scope_decision"] for h in self.hosts.values()
            ],
            "host_manifests": self.manifest["hosts"],
            "migration_marker": self.manifest["migration_marker"],
        }

    def export(self):
        state = self.journal.status()
        if state["qualified"] != 3 or state["pending"]:
            raise PoolStopped("three settled qualified observations required")
        refs = self.pool["imported_observations"][:]
        for attempt in self.pool["attempt_order"][: state["attempted"]]:
            child = next(
                c for c in self.pool["children"] if c["child_id"] == attempt["child_id"]
            )
            try:
                observation = read_native_observation(
                    child["evidence_root"], attempt["trial_id"]
                )
            except PermissionError:
                continue
            refs.append(
                {
                    "evidence_root": child["evidence_root"],
                    "trial_id": attempt["trial_id"],
                    "registration_sha256": observation["registration_sha256"],
                }
            )
        receipt = {
            "schema_version": pool_policy(self.pool).receipt_schema,
            "synthetic": False,
            "identity": self.pool["identity"],
            "formal_binding": self.pool["formal_binding"],
            "f8_approval_credit": 0,
            "distinct_case_count": 1,
            "measurement_replicates": 3,
            "controller_evidence": self.controller_evidence(),
            "pool_registration": self.pool,
            "pool_registration_sha256": self.digest,
            "observations": refs,
            "selected_trial_ids": [r["trial_id"] for r in refs],
            "observed_max_seconds": state["observed_max_seconds"],
        }
        validate_pool_receipt(receipt, self.pool["identity"])
        return receipt


def serve(controller, input_stream, output_stream):
    """One preloaded instance; explicit commands only; EOF never clears claims.

    The root UI owns its five-second reply poll and forwards only independently
    pinned actual chat records. This pipe cannot approve from text or timers.
    """

    def emit(value):
        output_stream.write(
            json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n"
        )
        output_stream.flush()

    emit({"status": "ready", "pool_sha256": controller.digest})
    for line in input_stream:
        try:
            command = _decode(line.encode("utf-8"))
            operation = command["operation"]
            if operation == "status" and set(command) == {"operation"}:
                result = controller.journal.status()
            elif operation == "export" and set(command) == {"operation"}:
                result = controller.export()
            elif operation in {"read", "trial"} and set(command) == {"operation"}:
                result = asyncio.run(controller.run(operation))
            elif operation == "plan" and set(command) == {
                "operation",
                "free_admission",
            }:
                result = asyncio.run(
                    controller.run("plan", free_admission_pin=command["free_admission"])
                )
            elif operation == "decision" and set(command) == {
                "operation",
                "packet_sha256",
                "chat_record",
            }:
                # Native decision verifies role=user, actual record pin, current
                # packet/TTL and host reader receipt; there is no auto decision.
                result = asyncio.run(
                    controller.run(
                        "decision",
                        packet_sha256=command["packet_sha256"],
                        chat_record=command["chat_record"],
                    )
                )
            elif operation == "audit-expiry" and set(command) == {
                "operation",
                "chat_records",
            }:
                result = asyncio.run(
                    controller.audit_expiry(chat_records=command["chat_records"])
                )
            elif operation == "review-guard" and set(command) == {"operation"}:
                result = controller.review_guard()
            elif operation == "resume" and set(command) == {"operation"}:
                result = asyncio.run(controller.resume())
            else:
                raise PoolStopped(
                    "explicit phase command and exact pinned fields required"
                )
            emit(result)
        except (OSError, ValueError, PermissionError, KeyError, TypeError) as error:
            emit(
                {
                    "status": "STOP",
                    "reason": str(error)
                    if isinstance(error, PoolStopped)
                    else type(error).__name__,
                }
            )
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation",
        choices=[
            "prepare",
            "status",
            "audit",
            "export",
            "run",
            "resume",
            "serve",
            "audit-expiry",
            "review-guard",
        ],
    )
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--phase", choices=["plan", "read", "decision", "trial"])
    parser.add_argument("--free-admission")
    parser.add_argument("--free-admission-sha256")
    parser.add_argument("--packet-sha256")
    parser.add_argument("--chat-record")
    parser.add_argument("--chat-record-sha256")
    args = parser.parse_args(argv)
    try:
        controller = NativePoolController(args.manifest, args.manifest_sha256)
        if args.operation == "serve":
            import sys

            return serve(controller, sys.stdin, sys.stdout)
        if args.operation == "prepare":
            result = asyncio.run(controller.prepare())
        elif args.operation == "audit-expiry":
            result = asyncio.run(
                controller.audit_expiry(
                    chat_records=[
                        {"path": args.chat_record, "sha256": args.chat_record_sha256}
                    ]
                    if args.chat_record
                    else []
                )
            )
        elif args.operation == "review-guard":
            result = controller.review_guard()
        elif args.operation == "resume":
            result = asyncio.run(controller.resume())
        elif args.operation == "run":
            if not args.phase:
                raise PoolStopped("explicit native phase required")
            result = asyncio.run(
                controller.run(
                    args.phase,
                    free_admission_pin={
                        "path": args.free_admission,
                        "sha256": args.free_admission_sha256,
                    }
                    if args.free_admission
                    else None,
                    packet_sha256=args.packet_sha256,
                    chat_record={
                        "path": args.chat_record,
                        "sha256": args.chat_record_sha256,
                    }
                    if args.chat_record
                    else None,
                )
            )
        elif args.operation == "export":
            result = controller.export()
        elif args.operation == "audit":
            controller.guard()
            result = {
                "journal": controller.journal.status(),
                "spent_yuan": str(controller.budget()),
                "quiescence": asyncio.run(controller.quiescence()),
            }
        else:
            result = controller.journal.status()
    except (OSError, ValueError, PermissionError, KeyError, TypeError) as error:
        print(json.dumps({"status": "STOP", "reason": str(error)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
